# Haldir Blog

Technical guides on AI agent governance, MCP security, and building production-ready agent systems.

---

## Posts

### [Why AI Agents Need a Governance Layer (And How to Build One)](./why-ai-agents-need-governance.md)
The problem of uncontrolled agents, what goes wrong without governance, and how to add identity, secrets management, and audit trails to your agent stack with Haldir.

### [MCP Proxy Mode: How to Intercept Every AI Agent Tool Call](./mcp-proxy-mode-explained.md)
How Haldir's proxy sits between agents and MCP servers, enforcing policies on every tool call. Covers allow/deny lists, spend limits, rate limits, time windows, and full audit logging.

### [Human-in-the-Loop for AI Agents: Approval Workflows That Actually Work](./human-in-the-loop-ai-agents.md)
Selective human oversight for sensitive agent actions. Approval rules, webhook integration, Slack notifications, auto-expiry, and the right balance between autonomy and control.

## Framework Integration Guides

### [How to Add Governance to LangChain Agents with Haldir](./haldir-langchain-integration.md)
Wrap LangChain tool calls with Haldir sessions, permission checks, and audit logging. Full Python code for governed tools, budget enforcement, and Vault integration.

### [Securing CrewAI Multi-Agent Systems with Haldir](./haldir-crewai-integration.md)
Give each CrewAI agent its own Haldir session with scoped permissions. Per-agent budget enforcement, secrets isolation, and audit trails across the entire crew.

### [Adding Identity and Audit to AutoGen Agents with Haldir](./haldir-autogen-integration.md)
Session-per-agent pattern for AutoGen conversations. Governed function calls, shared audit trail with per-agent attribution, and GroupChat governance.

### [How to Secure Any MCP Server with Haldir Proxy Mode](./secure-mcp-servers-with-haldir-proxy.md)
Step-by-step guide to routing all MCP tool calls through Haldir's proxy. Register upstreams, define policies (block_tool, spend_limit, rate_limit, time_window), and review the audit trail.

---

Get started: [haldir.xyz](https://haldir.xyz) | Install: `pip install haldir` | Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir)
