# Haldir Examples

Working examples that demonstrate the Haldir API for agent governance.

## Prerequisites

```bash
pip install httpx
```

All examples target `https://haldir.xyz` and use the bootstrap token for initial API key creation.

## Examples

### quickstart.py

Full lifecycle walkthrough covering every core feature in one script.

- Create an API key
- Create a scoped agent session with a spend limit
- Store and retrieve encrypted secrets (vault)
- Authorize a payment against the session budget
- Log actions to the audit trail
- Query the audit trail and spend summary
- Revoke the session

```bash
python3 examples/quickstart.py
```

### proxy_mode.py

Route all MCP tool calls through Haldir for mandatory governance.

- Register upstream MCP servers (Stripe, GitHub, etc.)
- Add policies: block dangerous tools, enforce spend limits, rate limit agents
- Call tools through the proxy (intercepted, authorized, forwarded)
- Inspect the audit trail for every proxied call
- Shows production MCP configuration for Claude, Cursor, etc.

```bash
python3 examples/proxy_mode.py
```

### human_in_the_loop.py

Approval workflows for sensitive agent actions.

- Add approval rules (spend thresholds, tool restrictions, destructive action gates)
- Agent requests approval when a rule is triggered
- Poll for approval status (agent side)
- Approve or deny from the human dashboard
- Agent proceeds or aborts based on the decision
- Includes a denial scenario for suspicious behavior

```bash
python3 examples/human_in_the_loop.py
```

### webhook_alerts.py

Real-time alerting for anomalies, budget exhaustion, and flagged actions.

- Register webhooks for Slack, Discord, or custom HTTP endpoints
- Configure per-webhook event filters (anomaly, budget_exhausted, flagged, etc.)
- Trigger actions that generate alerts (rapid-fire calls, budget exhaustion, suspicious commands)
- Review flagged entries in the audit trail
- Includes the webhook payload format for building integrations

```bash
python3 examples/webhook_alerts.py
```

## Framework Integrations

End-to-end examples using the native framework integration packages.

### langchain_agent.py

Governed research agent using `langchain-haldir`. Demonstrates `GovernedTool.from_tool`, `HaldirCallbackHandler`, `HaldirSecrets`, and `create_session` on a real LangChain ReAct agent.

```bash
pip install langchain-haldir langchain-openai duckduckgo-search
export OPENAI_API_KEY=sk-... HALDIR_API_KEY=hld_...
python3 examples/langchain_agent.py
```

### crewai_crew.py

Governed research crew using `crewai-haldir`. Wraps CrewAI's `SerperDevTool` with `GovernedTool.wrap`, including a `cost_fn` for variable per-call pricing.

```bash
pip install crewai crewai-tools crewai-haldir
export OPENAI_API_KEY=sk-... HALDIR_API_KEY=hld_... SERPER_API_KEY=...
python3 examples/crewai_crew.py
```

### vercel_ai_sdk.ts

Governed agent using `@haldir/ai-sdk`. Wraps an AI SDK tool with `governTool()` and runs it through `generateText`. Shows the full flow including `HaldirSecrets` usage.

```bash
npm install ai @ai-sdk/openai zod haldir @haldir/ai-sdk
export OPENAI_API_KEY=sk-... HALDIR_API_KEY=hld_...
npx tsx examples/vercel_ai_sdk.ts
```

## Common Patterns

### Authentication

Every request needs an API key via the `Authorization` header:

```python
headers = {
    "Authorization": "Bearer hld_your_key_here",
    "Content-Type": "application/json",
}
```

### Session Lifecycle

Sessions are the core unit of governance. Every agent action happens within a session:

```
Create session -> Check permissions -> Do work -> Log actions -> Revoke session
```

Sessions have scopes (read, write, execute), a TTL, and an optional spend limit.

### Error Handling

All examples use simple status code checks. In production, handle these:

- `401` -- Invalid or missing API key
- `403` -- Permission denied (scope, budget, or policy)
- `404` -- Resource not found (session expired, secret missing)
- `429` -- Rate limit exceeded

## API Reference

Full docs at https://haldir.xyz/docs
