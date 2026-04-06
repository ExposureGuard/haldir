/**
 * Haldir SDK — JavaScript client for the Haldir REST API.
 *
 * The guardian layer for AI agents: identity, secrets, audit.
 * Works with Node 18+ (native fetch). Zero dependencies.
 *
 * Usage:
 *   const { Client } = require('haldir');
 *   const h = new Client({ apiKey: 'hld_xxx' });
 *   const session = await h.createSession('my-agent', { scopes: ['read'] });
 */

"use strict";

// ── Errors ──────────────────────────────────────────────────────────────────

class HaldirError extends Error {
  /**
   * @param {string} message
   * @param {number} statusCode
   * @param {object} body
   */
  constructor(message, statusCode = 0, body = {}) {
    super(message);
    this.name = "HaldirError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

class HaldirAuthError extends HaldirError {
  /** Raised on 401 — invalid or missing API key. */
  constructor(message, body = {}) {
    super(message, 401, body);
    this.name = "HaldirAuthError";
  }
}

class HaldirPermissionError extends HaldirError {
  /** Raised on 403 — action not permitted (scope, budget, etc.). */
  constructor(message, body = {}) {
    super(message, 403, body);
    this.name = "HaldirPermissionError";
  }
}

class HaldirNotFoundError extends HaldirError {
  /** Raised on 404 — resource not found. */
  constructor(message, body = {}) {
    super(message, 404, body);
    this.name = "HaldirNotFoundError";
  }
}

// ── Client ──────────────────────────────────────────────────────────────────

class Client {
  /**
   * Create a Haldir API client.
   *
   * @param {object} options
   * @param {string} options.apiKey - Haldir API key (hld_xxx)
   * @param {string} [options.baseUrl='https://haldir.xyz'] - API base URL
   * @param {number} [options.timeout=30000] - Request timeout in ms
   */
  constructor({ apiKey, baseUrl = "https://haldir.xyz", timeout = 30000 } = {}) {
    if (!apiKey) {
      throw new HaldirError("apiKey is required");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeout = timeout;
  }

  /**
   * Internal: send an HTTP request and return parsed JSON.
   * @param {string} method
   * @param {string} path
   * @param {object} [options]
   * @param {object} [options.body] - JSON body
   * @param {object} [options.params] - Query parameters
   * @param {object} [options.headers] - Extra headers
   * @returns {Promise<object>}
   */
  async _request(method, path, { body, params, headers: extraHeaders } = {}) {
    let url = `${this.baseUrl}${path}`;

    // Append query parameters
    if (params && Object.keys(params).length > 0) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) {
          qs.append(k, String(v));
        }
      }
      url += `?${qs.toString()}`;
    }

    const headers = {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      ...extraHeaders,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let resp;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      if (err.name === "AbortError") {
        throw new HaldirError(`Request timed out after ${this.timeout}ms`);
      }
      throw new HaldirError(`Network error: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }

    // Parse response body
    let data;
    try {
      data = await resp.json();
    } catch {
      data = {};
    }

    // Raise typed errors
    if (!resp.ok) {
      const message = data.error || data.reason || resp.statusText;
      if (resp.status === 401) throw new HaldirAuthError(message, data);
      if (resp.status === 403) throw new HaldirPermissionError(message, data);
      if (resp.status === 404) throw new HaldirNotFoundError(message, data);
      throw new HaldirError(message, resp.status, data);
    }

    return data;
  }

  // ── Gate ────────────────────────────────────────────────────────────────

  /**
   * Create an agent session with scoped permissions and optional spend limit.
   *
   * @param {string} agentId - Unique agent identifier
   * @param {object} [options]
   * @param {string[]} [options.scopes] - Permission scopes (e.g. ['read', 'spend:50'])
   * @param {number} [options.ttl=3600] - Session TTL in seconds
   * @param {number} [options.spendLimit] - Max spend for this session in USD
   * @returns {Promise<object>} { session_id, agent_id, scopes, spend_limit, expires_at, ttl }
   */
  async createSession(agentId, { scopes, ttl = 3600, spendLimit } = {}) {
    const body = { agent_id: agentId, ttl };
    if (scopes !== undefined) body.scopes = scopes;
    if (spendLimit !== undefined) body.spend_limit = spendLimit;
    return this._request("POST", "/v1/sessions", { body });
  }

  /**
   * Retrieve session details including spend and validity status.
   *
   * @param {string} sessionId
   * @returns {Promise<object>}
   */
  async getSession(sessionId) {
    return this._request("GET", `/v1/sessions/${sessionId}`);
  }

  /**
   * Check whether a session has a specific permission scope.
   *
   * @param {string} sessionId
   * @param {string} scope - Scope to check (e.g. 'read', 'spend:50')
   * @returns {Promise<object>} { allowed, session_id, scope }
   */
  async checkPermission(sessionId, scope) {
    return this._request("POST", `/v1/sessions/${sessionId}/check`, {
      body: { scope },
    });
  }

  /**
   * Revoke an active session immediately.
   *
   * @param {string} sessionId
   * @returns {Promise<object>}
   */
  async revokeSession(sessionId) {
    return this._request("DELETE", `/v1/sessions/${sessionId}`);
  }

  // ── Vault ───────────────────────────────────────────────────────────────

  /**
   * Store an encrypted secret in the vault.
   *
   * @param {string} name - Secret name
   * @param {string} value - Secret value (encrypted at rest)
   * @param {object} [options]
   * @param {string} [options.scopeRequired='read'] - Scope needed to retrieve
   * @returns {Promise<object>} { stored, name }
   */
  async storeSecret(name, value, { scopeRequired = "read" } = {}) {
    return this._request("POST", "/v1/secrets", {
      body: { name, value, scope_required: scopeRequired },
    });
  }

  /**
   * Retrieve a secret by name. If sessionId is provided, scope is enforced.
   *
   * @param {string} name - Secret name
   * @param {object} [options]
   * @param {string} [options.sessionId] - Session for scope enforcement
   * @returns {Promise<object>} { name, value }
   */
  async getSecret(name, { sessionId } = {}) {
    const headers = {};
    if (sessionId) headers["X-Session-ID"] = sessionId;
    return this._request("GET", `/v1/secrets/${name}`, { headers });
  }

  /**
   * List all secret names in the vault.
   *
   * @returns {Promise<object>} { secrets, count }
   */
  async listSecrets() {
    return this._request("GET", "/v1/secrets");
  }

  /**
   * Delete a secret from the vault.
   *
   * @param {string} name - Secret name to delete
   * @returns {Promise<object>} { deleted, name }
   */
  async deleteSecret(name) {
    return this._request("DELETE", `/v1/secrets/${name}`);
  }

  // ── Payments ────────────────────────────────────────────────────────────

  /**
   * Authorize a payment against a session's spend limit.
   *
   * @param {string} sessionId
   * @param {number} amount - Amount in USD
   * @param {object} [options]
   * @param {string} [options.currency='USD']
   * @param {string} [options.description='']
   * @returns {Promise<object>} { authorized, amount, remaining_budget, ... }
   */
  async authorizePayment(sessionId, amount, { currency = "USD", description = "" } = {}) {
    return this._request("POST", "/v1/payments/authorize", {
      body: {
        session_id: sessionId,
        amount,
        currency,
        description,
      },
    });
  }

  // ── Watch ───────────────────────────────────────────────────────────────

  /**
   * Log an auditable action tied to a session.
   *
   * @param {string} sessionId
   * @param {object} [options]
   * @param {string} [options.tool=''] - Tool name (e.g. 'stripe')
   * @param {string} [options.action=''] - Action performed (e.g. 'charge')
   * @param {number} [options.costUsd=0] - Cost in USD
   * @param {object} [options.details] - Additional structured data
   * @returns {Promise<object>} { logged, entry_id, flagged, flag_reason }
   */
  async logAction(sessionId, { tool = "", action = "", costUsd = 0, details } = {}) {
    const body = {
      session_id: sessionId,
      tool,
      action,
      cost_usd: costUsd,
    };
    if (details !== undefined) body.details = details;
    return this._request("POST", "/v1/audit", { body });
  }

  /**
   * Query the audit trail with optional filters.
   *
   * @param {object} [options]
   * @param {string} [options.sessionId] - Filter by session
   * @param {string} [options.agentId] - Filter by agent
   * @param {string} [options.tool] - Filter by tool name
   * @param {boolean} [options.flaggedOnly=false] - Only flagged entries
   * @param {number} [options.limit=100] - Max entries to return
   * @returns {Promise<object>} { count, entries }
   */
  async getAuditTrail({ sessionId, agentId, tool, flaggedOnly = false, limit = 100 } = {}) {
    const params = { limit };
    if (sessionId) params.session_id = sessionId;
    if (agentId) params.agent_id = agentId;
    if (tool) params.tool = tool;
    if (flaggedOnly) params.flagged = "true";
    return this._request("GET", "/v1/audit", { params });
  }

  /**
   * Get spend summary, optionally filtered by session or agent.
   *
   * @param {object} [options]
   * @param {string} [options.sessionId] - Filter by session
   * @param {string} [options.agentId] - Filter by agent
   * @returns {Promise<object>} { total_usd, by_tool, ... }
   */
  async getSpend({ sessionId, agentId } = {}) {
    const params = {};
    if (sessionId) params.session_id = sessionId;
    if (agentId) params.agent_id = agentId;
    return this._request("GET", "/v1/audit/spend", { params });
  }

  // ── Approvals (Human-in-the-Loop) ──────────────────────────────────────

  /**
   * Create an approval rule (e.g. require human approval for spend > $100).
   *
   * @param {object} rule
   * @param {string} rule.tool - Tool pattern to match
   * @param {string} [rule.condition] - Condition expression
   * @param {string} [rule.action='require_approval'] - Action to take
   * @returns {Promise<object>}
   */
  async createApprovalRule(rule) {
    return this._request("POST", "/v1/approvals/rules", { body: rule });
  }

  /**
   * Request human approval for an action.
   *
   * @param {object} request
   * @param {string} request.session_id - Session requesting approval
   * @param {string} request.tool - Tool being called
   * @param {string} [request.action] - Action description
   * @param {object} [request.params] - Parameters for the action
   * @returns {Promise<object>} { request_id, status }
   */
  async requestApproval(request) {
    return this._request("POST", "/v1/approvals/request", { body: request });
  }

  /**
   * Get the status of an approval request.
   *
   * @param {string} requestId
   * @returns {Promise<object>}
   */
  async getApproval(requestId) {
    return this._request("GET", `/v1/approvals/${requestId}`);
  }

  /**
   * Approve a pending request.
   *
   * @param {string} requestId
   * @returns {Promise<object>}
   */
  async approveRequest(requestId) {
    return this._request("POST", `/v1/approvals/${requestId}/approve`);
  }

  /**
   * Deny a pending request.
   *
   * @param {string} requestId
   * @param {object} [options]
   * @param {string} [options.reason] - Denial reason
   * @returns {Promise<object>}
   */
  async denyRequest(requestId, { reason } = {}) {
    const body = reason ? { reason } : undefined;
    return this._request("POST", `/v1/approvals/${requestId}/deny`, { body });
  }

  /**
   * List pending approval requests.
   *
   * @returns {Promise<object>}
   */
  async listPendingApprovals() {
    return this._request("GET", "/v1/approvals/pending");
  }

  // ── Webhooks ────────────────────────────────────────────────────────────

  /**
   * Register a webhook for event notifications.
   *
   * @param {object} webhook
   * @param {string} webhook.url - Webhook delivery URL
   * @param {string[]} [webhook.events] - Events to subscribe to
   * @returns {Promise<object>}
   */
  async createWebhook(webhook) {
    return this._request("POST", "/v1/webhooks", { body: webhook });
  }

  /**
   * List registered webhooks.
   *
   * @returns {Promise<object>}
   */
  async listWebhooks() {
    return this._request("GET", "/v1/webhooks");
  }

  // ── Usage ───────────────────────────────────────────────────────────────

  /**
   * Get usage stats for the current billing period.
   *
   * @returns {Promise<object>}
   */
  async getUsage() {
    return this._request("GET", "/v1/usage");
  }
}

// ── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  Client,
  HaldirError,
  HaldirAuthError,
  HaldirPermissionError,
  HaldirNotFoundError,
};
