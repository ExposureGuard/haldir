"""
Tests for crewai_haldir.HaldirSession — the v0.2 two-line adoption path.

Matches the contract pattern from langchain-haldir: mint on enter,
revoke on exit (including on exception), env-driven by default,
explicit kwargs override env, stamp_sth works for dicts + objects +
bare values, STH-fetch errors never break the caller's output path.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _fake_client() -> MagicMock:
    c = MagicMock()
    c.create_session.return_value = {"session_id": "ses_crew_test"}
    c.revoke_session.return_value = {"revoked": True}
    c.get_tree_head.return_value = {
        "tree_size": 7,
        "root_hash": "cd" * 32,
        "algorithm": "Ed25519-over-canonical-sth",
        "key_id":    "feedfacecafebabe",
    }
    c.get_spend.return_value       = {"total_usd": 0.05, "action_count": 2}
    c.get_audit_trail.return_value = {"entries": [], "count": 0}
    return c


# ── Context-manager contract ────────────────────────────────────────

def test_session_mints_and_revokes(monkeypatch) -> None:
    from crewai_haldir import HaldirSession

    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("crew-1") as haldir:
            assert haldir.session_id == "ses_crew_test"
            assert haldir.client is client
        client.revoke_session.assert_called_once_with("ses_crew_test")


def test_session_revokes_on_exception(monkeypatch) -> None:
    from crewai_haldir import HaldirSession

    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with pytest.raises(RuntimeError):
            with HaldirSession.for_agent("crew-2"):
                raise RuntimeError("crew boom")
        client.revoke_session.assert_called_once()


def test_session_missing_api_key_raises() -> None:
    import os
    from crewai_haldir import HaldirSession
    os.environ.pop("HALDIR_API_KEY", None)
    with pytest.raises(RuntimeError, match="HALDIR_API_KEY"):
        HaldirSession(agent_id="x")


def test_explicit_api_key_beats_env(monkeypatch) -> None:
    from crewai_haldir import HaldirSession

    client = _fake_client()
    with patch(
        "crewai_haldir.session.HaldirClient", return_value=client,
    ) as C:
        monkeypatch.setenv("HALDIR_API_KEY", "hld_env")
        with HaldirSession(api_key="hld_explicit", agent_id="x"):
            pass
        assert C.call_args.kwargs["api_key"] == "hld_explicit"


# ── Spend / audit / STH helpers ─────────────────────────────────────

def test_spend_summary_forwards(monkeypatch) -> None:
    from crewai_haldir import HaldirSession
    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            spend = haldir.spend_summary()
    assert spend["total_usd"] == 0.05


def test_audit_trail_forwards(monkeypatch) -> None:
    from crewai_haldir import HaldirSession
    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            trail = haldir.audit_trail()
    assert trail["count"] == 0


def test_current_sth_returns_tree_head(monkeypatch) -> None:
    from crewai_haldir import HaldirSession
    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            sth = haldir.current_sth()
    assert sth["tree_size"] == 7
    assert sth["algorithm"].startswith("Ed25519")


# ── stamp_sth: the CrewAI-specific bit ─────────────────────────────

def test_stamp_sth_attaches_to_dict_result(monkeypatch) -> None:
    from crewai_haldir import HaldirSession
    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            result = haldir.stamp_sth({"output": "done"})
    assert result["output"] == "done"
    assert result["_haldir_sth"]["tree_size"] == 7


def test_stamp_sth_attaches_to_object_result(monkeypatch) -> None:
    """CrewAI's kickoff() returns a CrewOutput object (or similar).
    We need to attach the STH as an attribute."""
    from crewai_haldir import HaldirSession
    client = _fake_client()

    class FakeCrewOutput:
        def __init__(self):
            self.raw = "crew answer"

    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            result = haldir.stamp_sth(FakeCrewOutput())
    assert getattr(result, "_haldir_sth")["tree_size"] == 7


def test_stamp_sth_wraps_bare_value(monkeypatch) -> None:
    """If the result is a bare string / int / etc., wrap it into a
    dict so the STH has somewhere to live."""
    from crewai_haldir import HaldirSession
    client = _fake_client()
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            result = haldir.stamp_sth("bare string answer")
    assert result["output"] == "bare string answer"
    assert result["_haldir_sth"]["tree_size"] == 7


def test_stamp_sth_network_error_returns_original(monkeypatch) -> None:
    """A flaky tree-head fetch must NEVER alter the caller's result.
    This is the load-bearing invariant: we'd rather ship an
    un-stamped result than crash the crew."""
    from crewai_haldir import HaldirSession
    client = _fake_client()
    client.get_tree_head.side_effect = Exception("network blip")
    with patch("crewai_haldir.session.HaldirClient", return_value=client):
        monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
        with HaldirSession.for_agent("x") as haldir:
            result = haldir.stamp_sth({"output": "done"})
    assert result == {"output": "done"}
    assert "_haldir_sth" not in result
