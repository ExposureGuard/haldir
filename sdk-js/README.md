# Haldir — JavaScript SDK

The guardian layer for AI agents: identity, secrets, and audit.

Zero dependencies. Works with Node 18+ (native `fetch`).

## Install

```bash
npm install haldir
```

## Quick Start

```javascript
const { Client } = require('haldir');

const h = new Client({ apiKey: 'hld_xxx' });

// Create a governed agent session
const session = await h.createSession('my-agent', {
  scopes: ['read', 'spend:50'],
  ttl: 3600,
});

// Check permissions before acting
const perm = await h.checkPermission(session.session_id, 'read');
console.log(perm.allowed); // true

// Store secrets — agents never see raw keys
await h.storeSecret('stripe_key', 'sk_live_xxx');

// Retrieve with scope enforcement
const secret = await h.getSecret('stripe_key', {
  sessionId: session.session_id,
});

// Authorize payments against budget
await h.authorizePayment(session.session_id, 29.99, {
  description: 'API usage charge',
});

// Log every action for audit trail
await h.logAction(session.session_id, {
  tool: 'stripe',
  action: 'charge',
  costUsd: 29.99,
});

// Query audit trail
const trail = await h.getAuditTrail({ agentId: 'my-agent' });

// Get spend breakdown
const spend = await h.getSpend({ agentId: 'my-agent' });

// Revoke when done
await h.revokeSession(session.session_id);
```

## ESM Import

```javascript
import { Client } from 'haldir';
```

## API Reference

### Constructor

```javascript
const h = new Client({
  apiKey: 'hld_xxx',           // Required — your Haldir API key
  baseUrl: 'https://haldir.xyz', // Optional — API base URL
  timeout: 30000,              // Optional — request timeout in ms
});
```

### Gate (Identity & Auth)

| Method | Description |
|---|---|
| `createSession(agentId, { scopes, ttl, spendLimit })` | Create a scoped agent session |
| `getSession(sessionId)` | Get session details |
| `checkPermission(sessionId, scope)` | Check if session has a scope |
| `revokeSession(sessionId)` | Revoke a session |

### Vault (Secrets)

| Method | Description |
|---|---|
| `storeSecret(name, value, { scopeRequired })` | Store an encrypted secret |
| `getSecret(name, { sessionId })` | Retrieve a secret (scope-enforced if sessionId given) |
| `listSecrets()` | List all secret names |
| `deleteSecret(name)` | Delete a secret |

### Payments

| Method | Description |
|---|---|
| `authorizePayment(sessionId, amount, { currency, description })` | Authorize against budget |

### Watch (Audit & Compliance)

| Method | Description |
|---|---|
| `logAction(sessionId, { tool, action, costUsd, details })` | Log an auditable action |
| `getAuditTrail({ sessionId, agentId, tool, flaggedOnly, limit })` | Query audit trail |
| `getSpend({ sessionId, agentId })` | Get spend summary |

### Approvals (Human-in-the-Loop)

| Method | Description |
|---|---|
| `createApprovalRule(rule)` | Create an approval rule |
| `requestApproval(request)` | Request human approval |
| `getApproval(requestId)` | Check approval status |
| `approveRequest(requestId)` | Approve a pending request |
| `denyRequest(requestId, { reason })` | Deny a pending request |
| `listPendingApprovals()` | List pending approvals |

### Webhooks

| Method | Description |
|---|---|
| `createWebhook({ url, events })` | Register a webhook |
| `listWebhooks()` | List webhooks |

### Usage

| Method | Description |
|---|---|
| `getUsage()` | Get current billing period usage |

## Error Handling

All API errors throw typed exceptions:

```javascript
const { Client, HaldirAuthError, HaldirPermissionError, HaldirNotFoundError } = require('haldir');

try {
  await h.getSecret('nonexistent');
} catch (err) {
  if (err instanceof HaldirNotFoundError) {
    console.log('Secret not found');
  } else if (err instanceof HaldirAuthError) {
    console.log('Invalid API key');
  } else if (err instanceof HaldirPermissionError) {
    console.log('Insufficient permissions');
  }
  // All errors have: err.message, err.statusCode, err.body
}
```

## Error Classes

| Class | HTTP Status | When |
|---|---|---|
| `HaldirError` | any | Base class for all errors |
| `HaldirAuthError` | 401 | Invalid or missing API key |
| `HaldirPermissionError` | 403 | Scope or budget violation |
| `HaldirNotFoundError` | 404 | Resource not found |

## Requirements

- Node.js 18+ (uses native `fetch`)
- Zero dependencies

## Links

- [Haldir](https://haldir.xyz) — Live API
- [API Docs](https://haldir.xyz/docs) — Full endpoint reference
- [Python SDK](https://pypi.org/project/haldir/) — `pip install haldir`
- [GitHub](https://github.com/ExposureGuard/haldir)
