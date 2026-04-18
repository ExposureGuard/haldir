#!/usr/bin/env node

/**
 * Haldir JS SDK — Integration Test
 *
 * Runs the full Gate -> Vault -> Payments -> Watch lifecycle against the live API.
 *
 * Usage:
 *   HALDIR_API_KEY=hld_xxx node test.js
 *   HALDIR_API_KEY=hld_xxx HALDIR_BASE_URL=http://localhost:5000 node test.js
 */

"use strict";

const {
  Client,
  HaldirError,
  HaldirAuthError,
  HaldirPermissionError,
  HaldirNotFoundError,
} = require("./index.js");

const API_KEY = process.env.HALDIR_API_KEY;
const BASE_URL = process.env.HALDIR_BASE_URL || "https://haldir.xyz";

if (!API_KEY) {
  console.error("Set HALDIR_API_KEY to run tests.");
  console.error("  HALDIR_API_KEY=hld_xxx node test.js");
  process.exit(1);
}

let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  [+] ${name}`);
}

function fail(name, err) {
  failed++;
  console.log(`  [-] ${name}: ${err.message || err}`);
}

async function run() {
  console.log(`\nHaldir JS SDK — Integration Tests`);
  console.log(`Base URL: ${BASE_URL}\n`);

  const h = new Client({ apiKey: API_KEY, baseUrl: BASE_URL });

  // ── Gate ──

  console.log("Gate:");

  let session;
  try {
    session = await h.createSession("js-sdk-test", {
      scopes: ["read", "write", "spend:100"],
      ttl: 600,
      spendLimit: 100.0,
    });
    if (session.session_id && session.agent_id === "js-sdk-test") {
      ok(`createSession -> ${session.session_id}`);
    } else {
      fail("createSession", { message: `unexpected response: ${JSON.stringify(session)}` });
    }
  } catch (err) {
    fail("createSession", err);
    console.log("\nCannot continue without a session. Exiting.");
    process.exit(1);
  }

  try {
    const info = await h.getSession(session.session_id);
    if (info.session_id === session.session_id) {
      ok("getSession");
    } else {
      fail("getSession", { message: "session_id mismatch" });
    }
  } catch (err) {
    fail("getSession", err);
  }

  try {
    const perm = await h.checkPermission(session.session_id, "read");
    if (perm.allowed === true) {
      ok("checkPermission (read) -> allowed");
    } else {
      fail("checkPermission", { message: `expected allowed=true, got ${perm.allowed}` });
    }
  } catch (err) {
    fail("checkPermission", err);
  }

  // ── Vault ──

  console.log("\nVault:");

  const secretName = `js_test_${Date.now()}`;

  try {
    const stored = await h.storeSecret(secretName, "test_value_123");
    if (stored.stored === true || stored.name === secretName) {
      ok(`storeSecret -> ${secretName}`);
    } else {
      fail("storeSecret", { message: JSON.stringify(stored) });
    }
  } catch (err) {
    fail("storeSecret", err);
  }

  try {
    const secret = await h.getSecret(secretName, { sessionId: session.session_id });
    if (secret.value === "test_value_123") {
      ok("getSecret (with session) -> correct value");
    } else {
      fail("getSecret", { message: `value=${secret.value}` });
    }
  } catch (err) {
    fail("getSecret", err);
  }

  try {
    const list = await h.listSecrets();
    if (Array.isArray(list.secrets) && list.secrets.includes(secretName)) {
      ok(`listSecrets -> ${list.count} secrets, includes ${secretName}`);
    } else {
      fail("listSecrets", { message: JSON.stringify(list) });
    }
  } catch (err) {
    fail("listSecrets", err);
  }

  try {
    await h.deleteSecret(secretName);
    ok(`deleteSecret -> ${secretName}`);
  } catch (err) {
    fail("deleteSecret", err);
  }

  // Verify deletion
  try {
    await h.getSecret(secretName);
    fail("getSecret (deleted)", { message: "should have thrown 404" });
  } catch (err) {
    if (err instanceof HaldirNotFoundError) {
      ok("getSecret (deleted) -> 404 as expected");
    } else {
      fail("getSecret (deleted)", err);
    }
  }

  // ── Payments ──

  console.log("\nPayments:");

  try {
    const payment = await h.authorizePayment(session.session_id, 9.99, {
      description: "JS SDK test charge",
    });
    if (payment.authorized === true) {
      ok(`authorizePayment -> $9.99, remaining: $${payment.remaining_budget}`);
    } else {
      fail("authorizePayment", { message: JSON.stringify(payment) });
    }
  } catch (err) {
    fail("authorizePayment", err);
  }

  // ── Watch ──

  console.log("\nWatch:");

  try {
    const logged = await h.logAction(session.session_id, {
      tool: "test-sdk",
      action: "integration-test",
      costUsd: 0.01,
      details: { sdk: "javascript", version: "0.1.0" },
    });
    if (logged.logged === true && logged.entry_id) {
      ok(`logAction -> entry ${logged.entry_id}`);
    } else {
      fail("logAction", { message: JSON.stringify(logged) });
    }
  } catch (err) {
    fail("logAction", err);
  }

  try {
    const trail = await h.getAuditTrail({ agentId: "js-sdk-test", limit: 5 });
    if (trail.entries && trail.entries.length > 0) {
      ok(`getAuditTrail -> ${trail.count} entries`);
    } else {
      fail("getAuditTrail", { message: "no entries returned" });
    }
  } catch (err) {
    fail("getAuditTrail", err);
  }

  try {
    const spend = await h.getSpend({ agentId: "js-sdk-test" });
    if (spend.total_usd !== undefined) {
      ok(`getSpend -> $${spend.total_usd}`);
    } else {
      fail("getSpend", { message: JSON.stringify(spend) });
    }
  } catch (err) {
    fail("getSpend", err);
  }

  // ── Usage ──

  console.log("\nUsage:");

  try {
    const usage = await h.getUsage();
    ok(`getUsage -> ${JSON.stringify(usage)}`);
  } catch (err) {
    fail("getUsage", err);
  }

  // ── Cleanup ──

  console.log("\nCleanup:");

  try {
    await h.revokeSession(session.session_id);
    ok("revokeSession");
  } catch (err) {
    fail("revokeSession", err);
  }

  // ── Error handling ──

  console.log("\nError handling:");

  try {
    const bad = new Client({ apiKey: "invalid_key", baseUrl: BASE_URL });
    await bad.createSession("test");
    fail("bad API key", { message: "should have thrown" });
  } catch (err) {
    if (err instanceof HaldirAuthError) {
      ok("bad API key -> HaldirAuthError (401)");
    } else {
      fail("bad API key", { message: `expected HaldirAuthError, got ${err.constructor.name}: ${err.message}` });
    }
  }

  try {
    new Client({});
    fail("missing apiKey", { message: "should have thrown" });
  } catch (err) {
    if (err instanceof HaldirError && err.message.includes("apiKey")) {
      ok("missing apiKey -> HaldirError");
    } else {
      fail("missing apiKey", err);
    }
  }

  // ── Summary ──

  console.log(`\n${"=".repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log(`${"=".repeat(50)}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
