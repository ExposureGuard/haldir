<!-- mcp-name: io.github.ExposureGuard/haldir -->
# Haldir

**The guardian layer for AI agents.**

Haldir is an MCP server platform that gives AI agents identity, security, and accountability. Every agent action — browsing, paying, authenticating, calling APIs — flows through Haldir.

## Products

| Product | What it does | MCP Tools |
|---|---|---|
| **Haldir Gate** | Agent identity, auth, permissions | `authenticate`, `check_permission`, `create_session`, `revoke_session` |
| **Haldir Vault** | Secrets, credentials, payment limits | `get_secret`, `store_secret`, `authorize_payment`, `check_budget` |
| **Haldir Watch** | Audit logs, compliance, cost tracking | `log_action`, `get_audit_trail`, `get_spend`, `flag_anomaly` |

## Quick Start

```bash
pip install haldir
```

```python
from haldir import Gate, Vault, Watch

# Initialize
gate = Gate(api_key="your-key")
vault = Vault(api_key="your-key")
watch = Watch(api_key="your-key")

# Authenticate an agent
session = gate.create_session(agent_id="my-agent", scopes=["read", "spend:50"])

# Get a secret safely
api_key = vault.get_secret("stripe_key", session=session)

# Every action is logged
watch.log_action(session=session, tool="stripe", action="charge", amount=29.99)
```

## MCP Server

```json
{
  "mcpServers": {
    "haldir": {
      "command": "haldir-mcp",
      "env": {
        "HALDIR_API_KEY": "your-key"
      }
    }
  }
}
```

## Architecture

```
Agent (Claude, GPT, etc.)
    │
    ▼
┌─────────────────────────┐
│      Haldir Gate         │  ← Identity + permissions
│  "Can this agent do X?"  │
└────────┬────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│ Vault  │ │ Watch  │
│secrets │ │ audit  │
│payments│ │ costs  │
└────────┘ └────────┘
    │         │
    ▼         ▼
  External   Storage
  APIs       (Postgres)
```

## License

MIT
