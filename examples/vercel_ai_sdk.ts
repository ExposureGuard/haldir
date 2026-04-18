/**
 * Haldir + Vercel AI SDK — a governed agent with a weather tool.
 *
 * Uses governTool() to wrap any AI SDK tool so every invocation is
 * scope-checked against the Haldir session, cost-tracked, and written
 * to the hash-chained audit trail.
 *
 * Run:
 *   npm install ai @ai-sdk/openai zod haldir @haldir/ai-sdk
 *   export OPENAI_API_KEY=sk-...
 *   export HALDIR_API_KEY=hld_...
 *   npx tsx examples/vercel_ai_sdk.ts
 */

import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

import { createSession, governTool, HaldirSecrets } from '@haldir/ai-sdk';


async function main(): Promise<void> {
  // ── 1. Create a scoped Haldir session ────────────────────────────────
  const { client, sessionId } = await createSession({
    apiKey: process.env.HALDIR_API_KEY!,
    agentId: 'vercel-ai-weather-bot',
    scopes: ['read', 'search'],
    spendLimit: 1.0,
    ttl: 3600,
  });

  // ── 2. Retrieve secrets without leaking to the model (optional) ──────
  // const secrets = new HaldirSecrets(client, sessionId);
  // const apiKey = await secrets.get('weather_api_key');
  // const rawKey = apiKey.getValue();  // explicit unwrap — never auto-serializes

  // ── 3. Wrap an AI SDK tool with Haldir enforcement ───────────────────
  const weather = governTool({
    tool: tool({
      description: 'Get the current weather for a city',
      parameters: z.object({
        city: z.string().describe('The city name'),
      }),
      execute: async ({ city }: { city: string }) => {
        // In real code: call a weather API here, optionally unwrapping
        // the Haldir-stored API key. For the example we just return mock data.
        return `The weather in ${city} is sunny, 72°F.`;
      },
    }),
    client,
    sessionId,
    toolName: 'weather',
    requiredScope: 'read',
    costUsd: 0.001,           // flat per-call cost
  });

  // ── 4. Use exactly like any AI SDK tool ──────────────────────────────
  const { text } = await generateText({
    model: openai('gpt-4o-mini'),
    tools: { weather },
    prompt: 'What is the weather in San Francisco, Tokyo, and Greenville SC?',
    maxSteps: 5,
  });

  console.log('\n=== Agent response ===\n' + text);

  // ── 5. Inspect the audit trail ───────────────────────────────────────
  const trail = await client.getAuditTrail({ agentId: 'vercel-ai-weather-bot' });
  console.log(`\n=== Audit trail: ${trail.count} entries ===`);
  for (const entry of trail.entries ?? []) {
    const cost = (entry.cost_usd ?? 0).toFixed(4);
    console.log(`  [${entry.timestamp}] ${(entry.tool ?? '').padEnd(16)} $${cost}  (${entry.action ?? '-'})`);
  }

  const spend = await client.getSpend({ agentId: 'vercel-ai-weather-bot' });
  console.log(`\n=== Total spend: $${spend.total_usd.toFixed(4)} ===`);

  // ── 6. Kill the session ──────────────────────────────────────────────
  await client.revokeSession(sessionId);
  console.log('\nSession revoked. Further tool calls would throw HaldirPermissionError.');
}


main().catch((err) => {
  console.error(err);
  process.exit(1);
});
