"""
Unit tests for langchain-haldir using a mocked HaldirClient.

No network calls — exercises scope enforcement, audit logging, and cost tracking.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from langchain_haldir import GovernedTool, HaldirCallbackHandler, HaldirSecrets


class _DummyTool:
    """Stand-in for a LangChain BaseTool."""

    name = "search"
    description = "search the web"
    args_schema = None

    def _run(self, query: str) -> str:
        return f"results for {query}"

    async def _arun(self, query: str) -> str:
        return f"results for {query}"


def _mock_client(allowed: bool = True):
    client = MagicMock()
    client.check_permission.return_value = {"allowed": allowed}
    client.log_action.return_value = {"logged": True, "entry_id": "aud_x"}
    client.get_secret.return_value = {"value": "sk_live_xxx", "name": "stripe_key"}
    return client


def test_callback_logs_tool_end():
    client = _mock_client(allowed=True)
    cb = HaldirCallbackHandler(client, "ses_123", enforce=False)
    run_id = uuid4()

    cb.on_tool_start({"name": "search"}, "hello world", run_id=run_id)
    cb.on_tool_end("answer", run_id=run_id)

    client.log_action.assert_called_once()
    kwargs = client.log_action.call_args.kwargs
    assert kwargs["tool"] == "search"
    assert kwargs["action"] == "tool_call"
    assert "hello world" in kwargs["details"]["input"]
    assert "answer" in kwargs["details"]["output"]


def test_callback_enforces_scope():
    from sdk.client import HaldirPermissionError
    client = _mock_client(allowed=False)
    cb = HaldirCallbackHandler(client, "ses_123", enforce=True)

    with pytest.raises(HaldirPermissionError):
        cb.on_tool_start({"name": "search"}, "q", run_id=uuid4())


def test_callback_observability_mode_does_not_raise():
    client = _mock_client(allowed=False)
    cb = HaldirCallbackHandler(client, "ses_123", enforce=False)
    cb.on_tool_start({"name": "search"}, "q", run_id=uuid4())
    client.check_permission.assert_not_called()


def test_callback_scope_map_used():
    client = _mock_client(allowed=True)
    cb = HaldirCallbackHandler(
        client, "ses_123",
        scope_map={"search": "search"},
        default_scope="read",
        enforce=True,
    )
    cb.on_tool_start({"name": "search"}, "q", run_id=uuid4())
    args, _ = client.check_permission.call_args
    assert args[1] == "search"


def test_callback_default_scope_fallback():
    client = _mock_client(allowed=True)
    cb = HaldirCallbackHandler(client, "ses_123", default_scope="read", enforce=True)
    cb.on_tool_start({"name": "unmapped_tool"}, "q", run_id=uuid4())
    args, _ = client.check_permission.call_args
    assert args[1] == "read"


def test_callback_cost_fn_invoked():
    client = _mock_client(allowed=True)
    cb = HaldirCallbackHandler(
        client, "ses_123",
        enforce=False,
        cost_fn=lambda name, inp, out: 0.42,
    )
    run_id = uuid4()
    cb.on_tool_start({"name": "search"}, "q", run_id=run_id)
    cb.on_tool_end("done", run_id=run_id)
    assert client.log_action.call_args.kwargs["cost_usd"] == 0.42


def test_callback_error_path():
    client = _mock_client(allowed=True)
    cb = HaldirCallbackHandler(client, "ses_123", enforce=False)
    run_id = uuid4()
    cb.on_tool_start({"name": "search"}, "q", run_id=run_id)
    cb.on_tool_error(RuntimeError("boom"), run_id=run_id)
    kwargs = client.log_action.call_args.kwargs
    assert kwargs["action"] == "tool_error"
    assert "boom" in kwargs["details"]["error"]


def test_governed_tool_blocks_when_denied():
    from sdk.client import HaldirPermissionError
    client = _mock_client(allowed=False)
    tool = GovernedTool.from_tool(_DummyTool(), client, "ses_123", required_scope="search")

    with pytest.raises(HaldirPermissionError):
        tool._run("q")


def test_governed_tool_runs_when_allowed():
    client = _mock_client(allowed=True)
    tool = GovernedTool.from_tool(
        _DummyTool(), client, "ses_123",
        required_scope="search", cost_usd=0.05,
    )
    out = tool._run("cats")
    assert "cats" in out
    client.log_action.assert_called_once()
    assert client.log_action.call_args.kwargs["cost_usd"] == 0.05


def test_secrets_returns_secretstr():
    from pydantic import SecretStr
    client = _mock_client(allowed=True)
    secrets = HaldirSecrets(client, "ses_123")
    val = secrets.get("stripe_key")
    assert isinstance(val, SecretStr)
    assert val.get_secret_value() == "sk_live_xxx"
    client.get_secret.assert_called_once_with("stripe_key", session_id="ses_123")
