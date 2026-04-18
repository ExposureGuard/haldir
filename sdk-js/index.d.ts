/**
 * Haldir SDK — TypeScript type declarations for the JavaScript client.
 *
 * The guardian layer for AI agents: identity, secrets, audit.
 */

export class HaldirError extends Error {
  statusCode: number;
  body: Record<string, unknown>;
  constructor(message: string, statusCode?: number, body?: Record<string, unknown>);
}

export class HaldirAuthError extends HaldirError {
  constructor(message: string, body?: Record<string, unknown>);
}

export class HaldirPermissionError extends HaldirError {
  constructor(message: string, body?: Record<string, unknown>);
}

export class HaldirNotFoundError extends HaldirError {
  constructor(message: string, body?: Record<string, unknown>);
}

export interface ClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface Session {
  session_id: string;
  agent_id: string;
  scopes: string[];
  spend_limit?: number;
  expires_at: string;
  ttl: number;
}

export interface CreateSessionOptions {
  scopes?: string[];
  ttl?: number;
  spendLimit?: number;
}

export interface PermissionResult {
  allowed: boolean;
  session_id: string;
  scope: string;
}

export interface StoreSecretOptions {
  scopeRequired?: string;
}

export interface SecretResult {
  name: string;
  value: string;
}

export interface AuthorizePaymentOptions {
  currency?: string;
  description?: string;
}

export interface PaymentResult {
  authorized: boolean;
  amount: number;
  remaining_budget: number;
  [key: string]: unknown;
}

export interface LogActionOptions {
  tool?: string;
  action?: string;
  costUsd?: number;
  details?: Record<string, unknown>;
}

export interface AuditEntry {
  entry_id: string;
  session_id: string;
  tool: string;
  action: string;
  cost_usd?: number;
  timestamp: string;
  flagged?: boolean;
  [key: string]: unknown;
}

export interface GetAuditTrailOptions {
  sessionId?: string;
  agentId?: string;
  tool?: string;
  flaggedOnly?: boolean;
  limit?: number;
}

export interface AuditTrailResult {
  count: number;
  entries: AuditEntry[];
}

export interface GetSpendOptions {
  sessionId?: string;
  agentId?: string;
}

export interface SpendResult {
  total_usd: number;
  by_tool?: Record<string, number>;
  [key: string]: unknown;
}

export interface ApprovalRule {
  tool: string;
  condition?: string;
  action?: string;
  [key: string]: unknown;
}

export class Client {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeout: number;

  constructor(options: ClientOptions);

  createSession(agentId: string, options?: CreateSessionOptions): Promise<Session>;
  getSession(sessionId: string): Promise<Session>;
  checkPermission(sessionId: string, scope: string): Promise<PermissionResult>;
  revokeSession(sessionId: string): Promise<{ revoked: boolean; session_id: string }>;

  storeSecret(name: string, value: string, options?: StoreSecretOptions): Promise<{ stored: boolean; name: string }>;
  getSecret(name: string, options?: { sessionId?: string }): Promise<SecretResult>;
  listSecrets(): Promise<{ secrets: string[]; count: number }>;
  deleteSecret(name: string): Promise<{ deleted: boolean; name: string }>;

  authorizePayment(sessionId: string, amount: number, options?: AuthorizePaymentOptions): Promise<PaymentResult>;

  logAction(sessionId: string, options?: LogActionOptions): Promise<{ logged: boolean; entry_id: string; flagged?: boolean; flag_reason?: string }>;
  getAuditTrail(options?: GetAuditTrailOptions): Promise<AuditTrailResult>;
  getSpend(options?: GetSpendOptions): Promise<SpendResult>;

  createApprovalRule(rule: ApprovalRule): Promise<Record<string, unknown>>;
}
