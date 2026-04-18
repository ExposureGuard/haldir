# @haldir/ai-sdk

Governance layer for the [Vercel AI SDK](https://sdk.vercel.ai) — audit trails, spend caps, secrets vault, and instant revocation for every tool call.

Wrap any AI SDK tool with Haldir's enforcement proxy so every invocation is scope-checked, cost-tracked, and logged to a tamper-evident audit trail.

## Install

```bash
npm install @haldir/ai-sdk haldir
```

You'll need a Haldir API key. Create one free at [haldir.xyz](https://haldir.xyz).

## 30-second quickstart

```typescript
import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';
import { createSession, governTool } from '@haldir/ai-sdk';

// Create a scoped Haldir session with a $10 spend cap
const { client, sessionId } = await createSession({
  apiKey: process.env.HALDIR_API_KEY!,
  agentId: 'my-agent',
  scopes: ['read', 'search'],
  spendLimit: 10.0,
});

// Wrap your tool so Haldir enforces permissions
const weather = governTool({
  tool: tool({
    description: 'Get the weather in a city',
    parameters: z.object({ city: z.string() }),
    execute: async ({ city }) => `Weather in ${city}: sunny, 72°F.`,
  }),
  client,
  sessionId,
  toolName: 'weather',
  requiredScope: 'read',
  costUsd: 0.001,
});

// Use exactly like a normal AI SDK tool
const { text } = await generateText({
  model: openai('gpt-4o-mini'),
  tools: { weather },
  prompt: 'What is the weather in San Francisco?',
});
```

Every tool call is now:
- **Permission-checked** before execution (revoked or out-of-scope sessions throw `HaldirPermissionError`)
- **Cost-tracked** against the session's `spendLimit`
- **Logged** to Haldir's hash-chained audit trail with tool name, timestamp, and cost

## Variable cost per call

For tools whose cost depends on the output (e.g. paid APIs, token-metered models), pass `costFn`:

```typescript
const scraper = governTool({
  tool: myScraperTool,
  client,
  sessionId,
  toolName: 'scraper',
  requiredScope: 'read',
  costFn: (result) => JSON.stringify(result).length / 1000 * 0.005,
});
```

## Secrets without leaking them to the model

```typescript
import { HaldirSecrets } from '@haldir/ai-sdk';

// Store the secret once (out-of-band, not from the agent):
// await client.storeSecret('stripe_api_key', 'sk_live_xxx', { scopeRequired: 'spend' });

const secrets = new HaldirSecrets(client, sessionId);
const stripeKey = await secrets.get('stripe_api_key');

// stripeKey.toString() -> "[Haldir.Secret]"
// stripeKey.toJSON() -> "[Haldir.Secret]"
// Unwrap only where the raw value is actually needed:
const stripe = new Stripe(stripeKey.getValue());
```

If the session's scopes don't include the required scope, `secrets.get()` throws `HaldirPermissionError`.

## Revoking an agent mid-run

Any process with the Haldir API key can revoke the session — agent execution halts on the next tool call.

```typescript
await client.revokeSession(sessionId);  // next tool call throws HaldirPermissionError
```

Combined with approval webhooks (see [haldir.xyz/docs](https://haldir.xyz/docs)), this gives humans a kill switch over any running agent.

## Multiple tools, mixed scopes

```typescript
const scopes = ['read', 'search', 'execute', 'spend'];

const { client, sessionId } = await createSession({
  apiKey: process.env.HALDIR_API_KEY!,
  agentId: 'multi-tool-agent',
  scopes,
  spendLimit: 25.0,
});

const tools = {
  search:   governTool({ tool: searchTool,  client, sessionId, toolName: 'search',  requiredScope: 'search' }),
  runCode:  governTool({ tool: codeTool,    client, sessionId, toolName: 'runCode', requiredScope: 'execute' }),
  charge:   governTool({ tool: stripeTool,  client, sessionId, toolName: 'charge',  requiredScope: 'spend', costFn: (r: any) => r.amount / 100 }),
};

await generateText({
  model: openai('gpt-4o'),
  tools,
  prompt: '...',
});
```

Revoke the whole session when you need a kill switch:

```typescript
await client.revokeSession(sessionId);  // next tool call throws HaldirPermissionError
```

## Streaming

Works identically with `streamText`:

```typescript
import { streamText } from 'ai';

const result = await streamText({
  model: openai('gpt-4o'),
  tools: { weather },
  prompt: 'Weather in Tokyo?',
});

for await (const part of result.textStream) {
  process.stdout.write(part);
}
```

Every tool call inside the stream is governed exactly as with `generateText`.

## API

### `createSession(opts) => Promise<SessionHandle>`

- `apiKey` (required)
- `agentId` (required)
- `scopes?: string[]` — default `['read']`
- `ttl?: number` — seconds
- `spendLimit?: number` — USD cap
- `baseUrl?: string` — default `https://haldir.xyz`

Returns `{ client, sessionId }`.

### `governTool(opts) => Tool`

- `tool` (required) — an AI SDK tool with `execute`
- `client` (required)
- `sessionId` (required)
- `toolName` — used in audit logs (default `"unknown"`)
- `requiredScope` — default `"execute"`
- `costUsd` — fixed cost per call
- `costFn` — `(result) => number` for variable-cost tools

### `HaldirSecrets(client, sessionId).get(name) => Promise<Secret>`

Returns a `Secret` object. Call `.getValue()` to unwrap.

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/vercel-ai-haldir)
- Sibling packages: `langchain-haldir`, `crewai-haldir`

## License

MIT
