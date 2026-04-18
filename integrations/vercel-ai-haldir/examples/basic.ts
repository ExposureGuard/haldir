/**
 * Basic @haldir/ai-sdk example: governed weather tool.
 *
 * Run with:
 *   export OPENAI_API_KEY=sk-...
 *   export HALDIR_API_KEY=hld_...
 *   npx tsx examples/basic.ts
 */

import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

import { createSession, governTool } from '../src/index.js';

async function main(): Promise<void> {
  const { client, sessionId } = await createSession({
    apiKey: process.env.HALDIR_API_KEY!,
    agentId: 'example-weather-agent',
    scopes: ['read'],
    spendLimit: 1.0,
  });

  const weather = governTool({
    tool: tool({
      description: 'Get the current weather for a city',
      parameters: z.object({
        city: z.string().describe('The city to get weather for'),
      }),
      execute: async ({ city }) => {
        return `The weather in ${city} is sunny, 72°F.`;
      },
    }),
    client,
    sessionId,
    toolName: 'weather',
    requiredScope: 'read',
    costUsd: 0.001,
  });

  const { text } = await generateText({
    model: openai('gpt-4o-mini'),
    tools: { weather },
    prompt: 'What is the weather like in San Francisco?',
    maxSteps: 3,
  });

  console.log('\n=== Agent response ===');
  console.log(text);

  console.log('\n=== Audit trail ===');
  const trail = await client.getAuditTrail({ agentId: 'example-weather-agent' });
  for (const entry of trail.entries ?? []) {
    console.log(`  [${entry.timestamp}] ${entry.tool} — $${(entry.cost_usd ?? 0).toFixed(4)}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
