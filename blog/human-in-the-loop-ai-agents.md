# Human-in-the-Loop for AI Agents: Approval Workflows That Actually Work

*Published: April 2026 | Tags: human in the loop AI, agent approval workflow, AI agent oversight, MCP governance*

Every team building AI agents eventually hits the same wall: the agent needs to do something sensitive, and you need a human to sign off before it happens. Delete a database record. Send an email to a customer. Authorize a $500 charge. Deploy to production.

The naive solution is to disable autonomy entirely. Make the human approve everything. But that defeats the purpose of agents. You did not build an autonomous system to babysit it on every action.

The real solution is **selective human-in-the-loop**: define rules for which actions require approval, route them to the right person, and let everything else execute autonomously. This is how Haldir implements it, and it is the feature that makes enterprise teams say yes to agent deployment.

## Why HITL Matters More Than You Think

Consider what happens without human oversight on sensitive actions:

**A customer service agent** refunds $2,000 instead of $20 because the LLM misread the ticket. No approval step. The money is gone.

**A DevOps agent** tears down a staging environment that was actually production, because the environment variable was wrong. No human verified the target.

**A marketing agent** sends a campaign email to 50,000 subscribers with hallucinated content. Nobody reviewed the copy before send.

These are not edge cases. They are the predictable result of giving autonomous systems access to destructive operations without checkpoints. The question is not whether to add human oversight, but how to add it without destroying the agent's usefulness.

## Haldir's Approval System

Haldir's approval engine is built around three concepts: **rules**, **requests**, and **decisions**.

### Rules Define When Approval Is Needed

You define rules declaratively. When an agent action matches a rule, execution pauses and an approval request is created.

```bash
# Require approval for any spend over $100
curl -X POST https://haldir.xyz/v1/approvals/rules \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "spend_over",
    "threshold": 100,
    "notify": ["slack", "email"]
  }'

# Require approval for specific destructive tools
curl -X POST https://haldir.xyz/v1/approvals/rules \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "tool_match",
    "tools": ["delete_record", "send_email", "deploy_production"],
    "notify": ["webhook"]
  }'
```

Rule types include:

- **`spend_over`** - Any payment authorization above a threshold
- **`tool_match`** - Specific tools that always require approval
- **`scope_escalation`** - Agent requesting permissions beyond its session scope
- **`anomaly`** - Haldir Watch detects unusual behavior and flags it

### Requests Pause Agent Execution

When a rule triggers, Haldir creates a pending approval request and notifies the configured channels. The agent receives a "pending" status and can either wait or move on to other tasks.

```python
from haldir import HaldirClient

h = HaldirClient(api_key="hld_xxx")

session = h.create_session(
    agent_id="finance-bot",
    scopes=["read", "spend:500"]
)

# This triggers an approval because spend > $100 rule
try:
    h.authorize_payment(session["session_id"], amount=250.00)
except h.ApprovalRequired as e:
    print(f"Approval needed: {e.request_id}")
    print(f"Status: {e.status}")  # "pending"
    # Agent can poll or wait for webhook callback
```

The approval request contains everything the human needs to make a decision:

```json
{
  "request_id": "apr_x7k9m2",
  "session_id": "ses_a1b2c3d4",
  "agent_id": "finance-bot",
  "action": "authorize_payment",
  "tool": "stripe",
  "amount": 250.00,
  "reason": "Spend exceeds $100 threshold",
  "status": "pending",
  "created_at": "2026-04-05T14:30:00Z",
  "expires_at": "2026-04-05T15:30:00Z"
}
```

### Decisions Resume or Block

A human approves or denies through the API, the dashboard, or a webhook response:

```bash
# Approve
curl -X POST https://haldir.xyz/v1/approvals/apr_x7k9m2/approve \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "decided_by": "sterling@haldir.xyz",
    "note": "Verified against invoice #4821"
  }'

# Or deny
curl -X POST https://haldir.xyz/v1/approvals/apr_x7k9m2/deny \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "decided_by": "sterling@haldir.xyz",
    "note": "Amount does not match PO"
  }'
```

The decision, the decider, and the note are all recorded in the audit trail. This is the compliance record that regulated industries require.

## Webhook Integration

For real-time approval workflows, register a webhook. Haldir sends a POST to your endpoint whenever an approval is needed:

```bash
curl -X POST https://haldir.xyz/v1/webhooks \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/haldir-webhook",
    "events": ["approval.requested", "approval.expired"]
  }'
```

Your webhook handler receives:

```json
{
  "event": "approval.requested",
  "data": {
    "request_id": "apr_x7k9m2",
    "agent_id": "finance-bot",
    "action": "authorize_payment",
    "amount": 250.00,
    "reason": "Spend exceeds $100 threshold",
    "approve_url": "https://haldir.xyz/v1/approvals/apr_x7k9m2/approve",
    "deny_url": "https://haldir.xyz/v1/approvals/apr_x7k9m2/deny"
  }
}
```

This integrates directly with Slack, Discord, PagerDuty, or any internal approval tool. Post the webhook payload to a Slack channel. Add approve/deny buttons. The human clicks, the agent resumes. No context switching.

### Slack Integration Example

```python
import requests

def handle_haldir_webhook(payload):
    """Forward Haldir approval requests to Slack."""
    if payload["event"] == "approval.requested":
        data = payload["data"]
        slack_message = {
            "text": f"Agent *{data['agent_id']}* needs approval",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Action:* {data['action']}\n"
                            f"*Amount:* ${data['amount']:.2f}\n"
                            f"*Reason:* {data['reason']}"
                        )
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "url": data["approve_url"]
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "url": data["deny_url"]
                        }
                    ]
                }
            ]
        }
        requests.post(SLACK_WEBHOOK_URL, json=slack_message)
```

## Auto-Expiry Prevents Stale Requests

Approval requests have a configurable TTL. If nobody responds within the window, the request expires and the agent action is denied by default. This prevents stale requests from piling up and ensures agents do not hang indefinitely.

```python
# Check approval status (polling approach)
status = h.check_approval("apr_x7k9m2")

if status["status"] == "approved":
    # Proceed with the action
    h.authorize_payment(session["session_id"], amount=250.00)
elif status["status"] == "denied":
    # Log and move on
    print(f"Denied by {status['decided_by']}: {status['decision_note']}")
elif status["status"] == "expired":
    # Timed out — treat as denied
    print("Approval expired, action blocked")
```

## The Right Balance

The goal is not to approve everything. It is to approve the right things. A well-configured Haldir deployment might look like:

- **No approval needed:** Read operations, lookups, scans under $10
- **Auto-approve with logging:** Routine charges under $100, internal API calls
- **Human approval required:** External communications, charges over $100, destructive operations, production deployments

This gives agents the autonomy to be useful while keeping humans in control of the actions that matter.

## Getting Started

```bash
pip install haldir
```

Set up your first approval rule in under a minute. Your agents keep running. Your team stays in control.

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir)

---

*Haldir is the governance layer for AI agents. Human-in-the-loop approvals, encrypted secrets, immutable audit trails, and MCP proxy mode. Start free at [haldir.xyz](https://haldir.xyz).*
