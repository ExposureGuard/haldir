"""
Tests for llamaindex_haldir.HaldirSession — the v0.2 two-line path.

Mirrors the crewai-haldir test matrix exactly so an operator running
Haldir across both frameworks can verify parity.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _fake_client() -> MagicMock:
    c = MagicMock()
    c.create_session.return_value = {"session_id": "ses_li_test"}
    c.revoke_session.return_value = {"revoked": True}
    c.get_tree_head.return_value = {
        "tree_size": 11,
        "root_hash": "ab" * 32,
        "algorithm": "Ed25519-over-canonical-sth",
        "key_id":    "0123456789abcdef",
    }
    c.get_spend.return_value       = {"total_usd": 0.03, "action_count": 1}
    c.get_audit_trail.return_value = {"entries": [], "count": 0}
    return c


# ── Context-manager contract ────────────────────────────────────────

def test_session_mints_and_revokes(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession

    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("li-1") as haldir:
            assert haldir.session_id == "ses_li_test"
            assert haldir.client is client
        client.revoke_session.assert_called_once_with("ses_li_test")


def test_session_revokes_on_exception(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession

    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with pytest.raises(RuntimeError):
            with HaldirSession.for_agent("li-2"):
                raise RuntimeError("index boom")
        client.revoke_session.assert_called_once()


def test_session_missing_api_key_raises() -> None:
    import os
    from llamaindex_haldir import HaldirSession
    os.environ.pop("HALDIR_API_KEY", None)
    with pytest.raises(RuntimeError, match="HALDIR_API_KEY"):
        HaldirSession(agent_id="x")


def test_explicit_api_key_beats_env(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession

    client = _fake_client()
    with patch(
        "llamaindex_haldir.session.HaldirClient", return_value=client,
    ) as C:
        monkeypatch.setenv("HALDIR_API_KEY", "hld_env")
        with HaldirSession(api_key="hld_explicit", agent_id="x"):
            pass
        assert C.call_args.kwargs["api_key"] == "hld_explicit"


# ── Helpers ─────────────────────────────────────────────────────────

def test_spend_summary_forwards(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession
    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            spend = haldir.spend_summary()
    assert spend["total_usd"] == 0.03


def test_current_sth_returns_tree_head(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession
    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            sth = haldir.current_sth()
    assert sth["tree_size"] == 11


# ── stamp_sth: AgentChatResponse-style object attachment ────────────

def test_stamp_sth_attaches_to_agent_chat_response_style(monkeypatch) -> None:
    """LlamaIndex's .chat() returns an AgentChatResponse-like object
    with a .response attribute. stamp_sth must set _haldir_sth as an
    attribute on it without breaking the existing interface."""
    from llamaindex_haldir import HaldirSession
    client = _fake_client()

    class FakeAgentChatResponse:
        def __init__(self, response: str):
            self.response = response
            self.sources = []

    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            out = haldir.stamp_sth(FakeAgentChatResponse("the answer"))
    assert out.response == "the answer"
    assert out._haldir_sth["tree_size"] == 11


def test_stamp_sth_attaches_to_dict_result(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession
    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            out = haldir.stamp_sth({"response": "x"})
    assert out["_haldir_sth"]["tree_size"] == 11


def test_stamp_sth_wraps_bare_value(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession
    client = _fake_client()
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            out = haldir.stamp_sth("bare answer")
    assert out == {"output": "bare answer", "_haldir_sth": _fake_client().get_tree_head.return_value}


def test_stamp_sth_network_error_returns_original(monkeypatch) -> None:
    from llamaindex_haldir import HaldirSession
    client = _fake_client()
    client.get_tree_head.side_effect = Exception("network blip")
    with patch("llamaindex_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            out = haldir.stamp_sth({"response": "x"})
    assert out == {"response": "x"}
    assert "_haldir_sth" not in out
