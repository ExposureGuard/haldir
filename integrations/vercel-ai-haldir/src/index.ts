/**
 * @haldir/ai-sdk — Governance for Vercel AI SDK tools.
 *
 * Wrap any AI SDK tool with Haldir's enforcement layer: scope checks,
 * spend caps, audit trails, and instant revocation.
 *
 * Quick start:
 *
 *   import { generateText, tool } from 'ai';
 *   import { openai } from '@ai-sdk/openai';
 *   import { z } from 'zod';
 *   import { createSession, governTool } from '@haldir/ai-sdk';
 *
 *   const { client, sessionId } = await createSession({
 *     apiKey: process.env.HALDIR_API_KEY!,
 *     agentId: 'my-agent',
 *     scopes: ['read', 'search'],
 *     spendLimit: 10.0,
 *   });
 *
 *   const weather = governTool({
 *     tool: tool({
 *       description: 'Get weather',
 *       parameters: z.object({ city: z.string() }),
 *       execute: async ({ city }) => `Weather in ${city}: sunny.`,
 *     }),
 *     client, sessionId,
 *     requiredScope: 'read',
 *     costUsd: 0.001,
 *   });
 *
 *   await generateText({
 *     model: openai('gpt-4o-mini'),
 *     tools: { weather },
 *     prompt: 'What is the weather in SF?',
 *   });
 */

import { Client } from 'haldir';

// ── Session ──────────────────────────────────────────────────────────────────

export interface CreateSessionOptions {
  apiKey: string;
  agentId: string;
  scopes?: string[];
  ttl?: number;
  spendLimit?: number;
  baseUrl?: string;
}

export interface SessionHandle {
  client: Client;
  sessionId: string;
}

/** Create a Haldir client and a scoped session in one step. */
export async function createSession(opts: CreateSessionOptions): Promise<SessionHandle> {
  const client = new Client({
    apiKey: opts.apiKey,
    baseUrl: opts.baseUrl ?? 'https://haldir.xyz',
  });

  const session = await client.createSession(opts.agentId, {
    scopes: opts.scopes ?? ['read'],
    ttl: opts.ttl,
    spendLimit: opts.spendLimit,
  });

  return { client, sessionId: session.session_id };
}

// ── Tool governance ──────────────────────────────────────────────────────────

export class HaldirPermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HaldirPermissionError';
  }
}

/** A minimal shape for AI SDK tools — avoids a hard dep on ai internals. */
interface AISDKTool {
  description?: string;
  parameters: unknown;
  execute?: (args: unknown, options?: unknown) => Promise<unknown>;
}

export interface GovernToolOptions<T extends AISDKTool> {
  tool: T;
  client: Client;
  sessionId: string;
  requiredScope?: string;
  costUsd?: number;
  costFn?: (result: unknown) => number;
  toolName?: string;
}

/**
 * Wrap an AI SDK tool with Haldir enforcement.
 *
 * Every invocation:
 *   1. Checks scope against the Haldir session (pre-execution)
 *   2. Records the call + cost to the audit trail (post-execution)
 *   3. Throws HaldirPermissionError if the session is revoked or out-of-scope
 */
export function governTool<T extends AISDKTool>(opts: GovernToolOptions<T>): T {
  const {
    tool,
    client,
    sessionId,
    requiredScope = 'execute',
    costUsd = 0.0,
    costFn,
    toolName = 'unknown',
  } = opts;

  if (!tool.execute) {
    throw new Error(
      `governTool requires a tool with an execute() function. ` +
        `Client-side tools without execute cannot be governed.`,
    );
  }

  const originalExecute = tool.execute.bind(tool);

  const wrapped: T = {
    ...tool,
    execute: async (args: unknown, options?: unknown) => {
      const perm = await client.checkPermission(sessionId, requiredScope);
      if (!perm.allowed) {
        throw new HaldirPermissionError(
          `Tool '${toolName}' blocked: session lacks scope '${requiredScope}' or has been revoked.`,
        );
      }

      let result: unknown;
      try {
        result = await originalExecute(args, options);
      } catch (err) {
        await client
          .logAction(sessionId, {
            tool: toolName,
            action: 'error',
            details: { error: err instanceof Error ? err.message : String(err) },
          })
          .catch(() => undefined);
        throw err;
      }

      const cost = costFn ? costFn(result) : costUsd;
      await client
        .logAction(sessionId, {
          tool: toolName,
          action: 'execute',
          costUsd: cost,
        })
        .catch(() => undefined);

      return result;
    },
  };

  return wrapped;
}

// ── Secrets ──────────────────────────────────────────────────────────────────

/** Wrapper for a secret so it doesn't print in logs or stringify cleanly. */
export class Secret {
  #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  /** Unwrap the secret only where the value is actually used. */
  getValue(): string {
    return this.#value;
  }

  toString(): string {
    return '[Haldir.Secret]';
  }

  toJSON(): string {
    return '[Haldir.Secret]';
  }
}

export class HaldirSecrets {
  constructor(
    private client: Client,
    private sessionId: string,
  ) {}

  /** Retrieve a secret by name. Throws HaldirPermissionError if out-of-scope. */
  async get(name: string): Promise<Secret> {
    const result = await this.client.getSecret(name, { sessionId: this.sessionId });
    return new Secret(result.value);
  }
}
