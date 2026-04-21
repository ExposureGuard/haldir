"""
Tests for HaldirSession context manager, HaldirCallbackHandler.from_env,
LLM cost auto-tracking, and STH stamping at agent-finish.

These are the four surfaces the v0.2 distribution wedge hangs on — if
any of them break, the "2 lines of code" promise in the README is
broken. Pin them explicitly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


# ── HaldirSession context manager ──────────────────────────────────

def _fake_client(**overrides) -> MagicMock:
    client = MagicMock()
    client.create_session.return_value = {
        "session_id": overrides.get("session_id", "ses_test_123"),
        "agent_id":   "fake-agent",
        "scopes":     ["read"],
    }
    client.revoke_session.return_value = {"revoked": True}
    client.check_permission.return_value = {"allowed": True}
    client.log_action.return_value = {"logged": True, "entry_id": "aud_x"}
    client.get_tree_head.return_value = {
        "tree_size":  42,
        "root_hash":  "abcd" * 16,
        "signature":  "ff" * 64,
        "algorithm":  "Ed25519-over-canonical-sth",
        "key_id":     "deadbeefcafebabe",
    }
    client.get_spend.return_value = {"total_usd": 0.12, "action_count": 3}
    client.get_audit_trail.return_value = {"entries": [], "count": 0}
    return client


def test_session_mints_on_enter_and_revokes_on_exit(monkeypatch) -> None:
    from langchain_haldir import HaldirSession

    client = _fake_client()
    with patch("langchain_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("test-bot") as s:
            assert s.session_id == "ses_test_123"
            assert s.handler is not None
        # Must revoke on exit.
        client.revoke_session.assert_called_once_with("ses_test_123")


def test_session_revokes_even_on_exception(monkeypatch) -> None:
    from langchain_haldir import HaldirSession

    client = _fake_client()
    with patch("langchain_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with pytest.raises(RuntimeError):
            with HaldirSession.for_agent("test-bot"):
                raise RuntimeError("boom from user code")
        # Revoke ran despite the exception.
        client.revoke_session.assert_called_once()


def test_session_missing_api_key_raises() -> None:
    from langchain_haldir import HaldirSession
    import os
    os.environ.pop("HALDIR_API_KEY", None)
    with pytest.raises(RuntimeError, match="HALDIR_API_KEY"):
        HaldirSession(agent_id="x")


def test_session_explicit_api_key_overrides_env(monkeypatch) -> None:
    from langchain_haldir import HaldirSession

    client = _fake_client()
    with patch(
        "langchain_haldir.session.HaldirClient", return_value=client,
    ) as C:
        monkeypatch.setenv("HALDIR_API_KEY", "hld_env_key")
        with HaldirSession(api_key="hld_explicit_key", agent_id="x"):
            pass
        # Client was built with the explicit key, not the env one.
        args, kwargs = C.call_args
        assert kwargs["api_key"] == "hld_explicit_key"


def test_session_helpers_forward_to_client(monkeypatch) -> None:
    from langchain_haldir import HaldirSession

    client = _fake_client()
    with patch("langchain_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as s:
            spend = s.spend_summary()
            audit = s.audit_trail()
            sth   = s.current_sth()
        assert spend["total_usd"] == 0.12
        assert audit["count"] == 0
        assert sth["tree_size"] == 42


# ── HaldirCallbackHandler.from_env ──────────────────────────────────

def test_from_env_builds_handler_with_client(monkeypatch) -> None:
    from langchain_haldir import HaldirCallbackHandler

    with patch("langchain_haldir.callback.HaldirClient") as C:
        C.return_value = MagicMock()
        monkeypatch.setenv("HALDIR_API_KEY", "hld_from_env")
        h = HaldirCallbackHandler.from_env(session_id="ses_abc")
        assert h.session_id == "ses_abc"
        C.assert_called_once()
        assert C.call_args.kwargs["api_key"] == "hld_from_env"


def test_from_env_missing_key_raises(monkeypatch) -> None:
    from langchain_haldir import HaldirCallbackHandler
    monkeypatch.delenv("HALDIR_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="HALDIR_API_KEY"):
        HaldirCallbackHandler.from_env(session_id="ses_abc")


# ── LLM cost auto-tracking via on_llm_end ───────────────────────────

def _llm_result(prompt_tokens: int, completion_tokens: int,
                 shape: str = "llm_output") -> Any:
    """Build a LangChain LLMResult in one of its three canonical
    usage-reporting shapes so the extractor is exercised per-shape."""
    from langchain_core.outputs import LLMResult, Generation

    if shape == "llm_output":
        return LLMResult(
            generations=[[Generation(text="x")]],
            llm_output={"token_usage": {
                "prompt_tokens":     prompt_tokens,
                "completion_tokens": completion_tokens,
            }},
        )
    if shape == "generation_info":
        return LLMResult(
            generations=[[Generation(
                text="x",
                generation_info={"token_usage": {
                    "prompt_tokens":     prompt_tokens,
                    "completion_tokens": completion_tokens,
                }},
            )]],
            llm_output=None,
        )
    raise ValueError(f"unknown shape: {shape}")


def test_on_llm_end_writes_cost_from_pricing_table() -> None:
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses", track_llm_cost=True)
    run_id = uuid4()
    h.on_llm_start({"kwargs": {"model": "gpt-4o-mini"}}, ["hi"], run_id=run_id)
    h.on_llm_end(_llm_result(1000, 500), run_id=run_id)

    # GPT-4o-mini: $0.15 / 1M prompt, $0.60 / 1M completion
    # 1000 prompt = 0.00015, 500 completion = 0.00030 → 0.00045 total.
    call = client.log_action.call_args
    kwargs = call.kwargs
    assert kwargs["action"] == "llm_call"
    assert kwargs["tool"]   == "llm:gpt-4o-mini"
    assert kwargs["cost_usd"] == pytest.approx(0.000450, abs=1e-6)
    assert kwargs["details"]["prompt_tokens"]     == 1000
    assert kwargs["details"]["completion_tokens"] == 500


def test_on_llm_end_uses_generation_info_shape() -> None:
    """Different providers report usage in different places. The
    extractor must pick it up from generation_info when llm_output
    is None."""
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses")
    run_id = uuid4()
    h.on_llm_start({"kwargs": {"model": "claude-3-5-sonnet"}},
                    ["hi"], run_id=run_id)
    h.on_llm_end(_llm_result(100, 50, shape="generation_info"),
                 run_id=run_id)
    kwargs = client.log_action.call_args.kwargs
    # Claude 3.5 Sonnet: $3/1M prompt, $15/1M completion → 100*3e-6 + 50*15e-6 = 0.001050
    assert kwargs["cost_usd"] == pytest.approx(0.001050, abs=1e-6)


def test_on_llm_end_noop_when_tracking_disabled() -> None:
    from langchain_haldir import HaldirCallbackHandler
    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses", track_llm_cost=False)
    run_id = uuid4()
    h.on_llm_start({"kwargs": {"model": "gpt-4o"}}, ["hi"], run_id=run_id)
    h.on_llm_end(_llm_result(1000, 500), run_id=run_id)
    client.log_action.assert_not_called()


def test_on_llm_end_unknown_model_falls_back_to_conservative_rate() -> None:
    """Unknown models SHOULD bill HIGH (via the _FALLBACK rate) so a
    budget fires early rather than blowing through silently."""
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses")
    run_id = uuid4()
    h.on_llm_start({"kwargs": {"model": "made-up-model-2099"}},
                    ["hi"], run_id=run_id)
    h.on_llm_end(_llm_result(1_000_000, 1_000_000), run_id=run_id)
    kwargs = client.log_action.call_args.kwargs
    # _FALLBACK is $15/$75 per 1M → $15 + $75 = $90 for 1M of each.
    assert kwargs["cost_usd"] == pytest.approx(90.0, abs=0.01)


# ── STH stamping on on_agent_finish ──────────────────────────────────

def test_on_agent_finish_stamps_sth_into_return_values() -> None:
    from langchain_core.agents import AgentFinish
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses", stamp_sth=True)

    finish = AgentFinish(return_values={"output": "done"}, log="")
    h.on_agent_finish(finish, run_id=uuid4())
    assert "_haldir_sth" in finish.return_values
    sth = finish.return_values["_haldir_sth"]
    assert sth["tree_size"] == 42
    assert sth["algorithm"] == "Ed25519-over-canonical-sth"


def test_on_agent_finish_noop_when_disabled() -> None:
    from langchain_core.agents import AgentFinish
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    h = HaldirCallbackHandler(client, "ses", stamp_sth=False)
    finish = AgentFinish(return_values={"output": "done"}, log="")
    h.on_agent_finish(finish, run_id=uuid4())
    assert "_haldir_sth" not in finish.return_values
    client.get_tree_head.assert_not_called()


def test_on_agent_finish_swallows_network_errors() -> None:
    """A flaky tree-head fetch must NEVER break the agent's return
    path. The agent owns the success semantics; the STH stamp is a
    best-effort add-on."""
    from langchain_core.agents import AgentFinish
    from langchain_haldir import HaldirCallbackHandler

    client = _fake_client()
    client.get_tree_head.side_effect = Exception("network blip")
    h = HaldirCallbackHandler(client, "ses", stamp_sth=True)
    finish = AgentFinish(return_values={"output": "done"}, log="")
    # Should not raise; should not stamp.
    h.on_agent_finish(finish, run_id=uuid4())
    assert "_haldir_sth" not in finish.return_values
    assert finish.return_values["output"] == "done"


# ── Pricing table unit-level ──────────────────────────────────────

def test_pricing_longest_prefix_wins() -> None:
    from langchain_haldir.pricing import price_for

    # "gpt-4o-mini" should beat "gpt-4" even though both prefix-match.
    assert price_for("gpt-4o-mini-2024-07-18")["prompt"] == 0.15
    assert price_for("gpt-4-turbo")["prompt"] == 10.00
    assert price_for("claude-opus-4-2026-01-01")["prompt"] == 15.00


def test_pricing_unknown_model_returns_fallback() -> None:
    from langchain_haldir.pricing import price_for, _FALLBACK
    assert price_for("not-a-real-model")["prompt"] == _FALLBACK["prompt"]
    assert price_for(None)["prompt"] == _FALLBACK["prompt"]


def test_cost_usd_returns_zero_for_zero_tokens() -> None:
    from langchain_haldir.pricing import cost_usd
    assert cost_usd("gpt-4o", 0, 0) == 0.0
    assert cost_usd(None, 100, 100) > 0  # fallback rate still applies
