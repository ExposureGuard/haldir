#!/usr/bin/env python3
"""
Haldir tester probes — three things worth trying to break.

    haldir serve                # in one terminal
    python3 -m haldir_probes    # in another

Stdlib only, no account, nothing to install. It mints a demo key, drives
three probes against the running instance, and prints what it observed.
Exit code is 0 only if every probe passed.

The probes are the three a reviewer of this project said they would break
first, so they are the three worth handing over pre-broken:

  Probe 1 — mid-call revocation
      Is revocation enforced on every call, or cached when the session was
      created? Creates a session, confirms a granted scope is allowed,
      revokes, and asks again. It also asks for a scope that was NEVER
      granted, as a control — otherwise a check that simply always answers
      "no" would pass this probe.

  Probe 2 — timeout after commit
      A client POSTs, the server commits, and the response is lost in
      flight. The client retries. Does the server do the work twice?
      Sends one Idempotency-Key twice and confirms the second call returns
      the first response without a second audit entry. Then reuses that key
      with a DIFFERENT body and expects a 422, because a key that silently
      accepts a different body is not idempotency.

  Probe 3 — audit read-back after reconnect
      A fresh connection reads back what a previous client wrote, and
      verifies the chain. Then it edits one row in the SQLite file behind
      the server's back and confirms verification FAILS — because a
      verifier that cannot fail is not evidence of anything. The row is
      restored afterwards.

This is a fixture, not a test suite: it asserts current behaviour so you
can disagree with it. Every probe prints the raw responses it based its
verdict on, so a FAIL can be checked by hand rather than taken on faith.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid

DEFAULT_BASE = os.environ.get("HALDIR_BASE_URL", "http://127.0.0.1:8000")

# Distinctive enough to find in the audit log, and never a real action name.
PROBE_ACTION = "probe.timeout_after_commit"


# ── Output ──────────────────────────────────────────────────────────────
# Same status prefixes the rest of the project uses.

def banner(text: str) -> None:
    print(f"\n── {text} ──")


def info(text: str) -> None:
    print(f"[*] {text}")


def good(text: str) -> None:
    print(f"[+] {text}")


def bad(text: str) -> None:
    print(f"[-] {text}")


def evidence(label: str, value: object) -> None:
    """Print the raw thing a verdict was based on, indented under it."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    print(f"      {label}: {value}")


# ── HTTP ────────────────────────────────────────────────────────────────

class Client:
    """One HTTP client against one instance.

    Each call opens its own connection and sends `Connection: close`, so
    there is no keep-alive socket quietly carrying state between probes.
    That is what makes probe 3's "reconnect" mean something.
    """

    def __init__(self, base: str, api_key: str | None = None):
        self.base = base.rstrip("/")
        self.api_key = api_key

    def call(self, method: str, path: str, body: dict | None = None,
             idem: str | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Connection", "close")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        if idem:
            req.add_header("Idempotency-Key", idem)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode()
                return resp.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, {"raw": raw}

    def audit_count(self) -> int:
        _, body = self.call("GET", "/v1/audit")
        return int(body.get("count", 0))


def new_session(c: Client, scopes: list[str], agent: str = "probe-agent") -> str | None:
    status, body = c.call("POST", "/v1/sessions", {
        "agent_id": agent,
        "scopes": scopes,
        "spend_limit": 100,
    })
    if status not in (200, 201):
        bad(f"could not create a session (HTTP {status})")
        evidence("response", body)
        return None
    return body.get("session_id")


def allowed(c: Client, session_id: str, scope: str) -> bool | None:
    """Ask the gate. Returns None if the call itself failed, so a transport
    error is never mistaken for a denial."""
    status, body = c.call("POST", f"/v1/sessions/{session_id}/check", {"scope": scope})
    if status != 200:
        return None
    return bool(body.get("allowed"))


# ── Probe 1 ─────────────────────────────────────────────────────────────

def probe_mid_call_revocation(c: Client) -> bool:
    banner("Probe 1 — mid-call revocation")
    info("A session is created, used, revoked, and asked to act again.")

    sid = new_session(c, ["read", "execute"])
    if not sid:
        return False
    evidence("session", sid)

    # Control first: a scope that was never granted must already be denied.
    # Without this, a gate that answers "no" to everything would pass.
    control = allowed(c, sid, "delete")
    info(f"scope 'delete' (never granted) before revocation -> {control}")
    if control is not False:
        bad("a never-granted scope was not denied — the gate is not checking scopes")
        return False
    good("never-granted scope correctly denied (control)")

    before = allowed(c, sid, "read")
    info(f"scope 'read' (granted) before revocation -> {before}")
    if before is not True:
        bad("a granted scope was denied before revocation — probe cannot proceed")
        return False
    good("granted scope allowed before revocation")

    status, body = c.call("DELETE", f"/v1/sessions/{sid}")
    evidence("DELETE /v1/sessions/<id>", f"HTTP {status}")
    if status not in (200, 204):
        bad(f"revocation failed (HTTP {status})")
        evidence("response", body)
        return False
    good("session revoked")

    after = allowed(c, sid, "read")
    info(f"scope 'read' after revocation -> {after}")
    if after is not False:
        bad("a revoked session was still allowed to act — revocation was cached")
        return False
    good("revoked session denied on the next call")

    # Revocation must also close the OTHER granted scope, not just the one
    # we happened to test.
    other = allowed(c, sid, "execute")
    info(f"scope 'execute' after revocation -> {other}")
    if other is not False:
        bad("a revoked session kept a second granted scope open")
        return False
    good("every granted scope closes together")

    print("\n  Verdict: revocation is enforced per call, not cached.")
    return True


# ── Probe 2 ─────────────────────────────────────────────────────────────

def probe_timeout_after_commit(c: Client) -> bool:
    banner("Probe 2 — timeout after commit")
    info("One POST is sent twice under the same Idempotency-Key.")
    info("This is the shape of a request that committed but whose response")
    info("was lost — the client never saw success, so it retries.")

    sid = new_session(c, ["read", "execute", "audit:write"])
    if not sid:
        return False

    body = {"session_id": sid, "action": PROBE_ACTION, "tool": "probe",
            "details": {"note": "timeout-after-commit probe"}}
    key = str(uuid.uuid4())
    evidence("Idempotency-Key", key)

    before = c.audit_count()
    evidence("audit entries before", before)

    st1, first = c.call("POST", "/v1/audit", body, idem=key)
    evidence("first POST", f"HTTP {st1} {json.dumps(first)}")
    if st1 not in (200, 201):
        bad(f"the first write failed (HTTP {st1}) — probe cannot proceed")
        return False

    st2, second = c.call("POST", "/v1/audit", body, idem=key)
    evidence("retry (same key, same body)", f"HTTP {st2} {json.dumps(second)}")

    after = c.audit_count()
    evidence("audit entries after", after)

    if after != before + 1:
        bad(f"the retry wrote again: {before} -> {after} entries (expected +1)")
        return False
    good(f"the retry did not duplicate work ({before} -> {after})")

    if second.get("entry_id") != first.get("entry_id"):
        bad("the retry returned a different entry than the original")
        evidence("first entry_id", first.get("entry_id"))
        evidence("retry entry_id", second.get("entry_id"))
        return False
    good(f"the retry returned the original response ({first.get('entry_id')})")

    # The other half of the contract: a reused key with a different body is
    # a client bug, and must not be silently accepted as the first request.
    st3, third = c.call("POST", "/v1/audit",
                        {**body, "action": PROBE_ACTION + ".different"},
                        idem=key)
    evidence("same key, DIFFERENT body", f"HTTP {st3} {json.dumps(third)}")
    if st3 != 422:
        bad(f"a reused key with a different body returned HTTP {st3}, expected 422")
        return False
    good("a reused key with a different body is rejected (422)")

    final = c.audit_count()
    if final != after:
        bad(f"the rejected request still wrote ({after} -> {final})")
        return False

    print("\n  Verdict: a retry after a lost response is safe, and a key")
    print("  reused against a different body is refused rather than obeyed.")
    return True


# ── Probe 3 ─────────────────────────────────────────────────────────────

def find_db(explicit: str | None) -> str | None:
    """Locate the SQLite file for the tamper control.

    Only used to prove the verifier can fail. Everything else in this
    probe works over HTTP; if the file isn't reachable the control is
    skipped rather than faked.
    """
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for cand in ("haldir.db", os.path.expanduser("~/.haldir/haldir.db")):
        if os.path.exists(cand):
            return cand
    return None


def tamper(db_path: str, entry_id: str) -> tuple[bool, str]:
    """Edit a row's action in place, leaving its hash untouched. Returns
    (applied, original_action) so the caller can put it back."""
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        row = conn.execute(
            "SELECT action FROM audit_log WHERE entry_id = ?", (entry_id,)
        ).fetchone()
        if not row:
            return False, ""
        original = row[0]
        conn.execute(
            "UPDATE audit_log SET action = ? WHERE entry_id = ?",
            (original + " [edited by haldir_probes.py]", entry_id),
        )
        conn.commit()
        return True, original
    finally:
        conn.close()


def restore(db_path: str, entry_id: str, original: str) -> None:
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute("UPDATE audit_log SET action = ? WHERE entry_id = ?",
                     (original, entry_id))
        conn.commit()
    finally:
        conn.close()


def probe_audit_readback(c: Client, db_path: str | None) -> bool:
    banner("Probe 3 — audit read-back after reconnect")
    info("A second client, on a fresh connection, reads back what the")
    info("first one wrote — then we try to make the verifier lie.")

    sid = new_session(c, ["read", "execute", "audit:write"])
    if not sid:
        return False

    marker = f"probe.readback.{uuid.uuid4().hex[:8]}"
    st, wrote = c.call("POST", "/v1/audit",
                       {"session_id": sid, "action": marker, "tool": "probe"})
    if st not in (200, 201):
        bad(f"could not write an entry to read back (HTTP {st})")
        evidence("response", wrote)
        return False
    entry_id = wrote.get("entry_id")
    if not isinstance(entry_id, str) or not entry_id:
        bad("the write returned no entry_id — probe cannot proceed")
        evidence("response", wrote)
        return False
    evidence("wrote entry", entry_id)

    # Reconnect: a brand new client object, and every Client.call opens its
    # own connection anyway. Nothing from the write is being reused.
    fresh = Client(c.base, c.api_key)
    status, listing = fresh.call("GET", "/v1/audit")
    evidence("GET /v1/audit on the new connection", f"HTTP {status}, count={listing.get('count')}")
    if status != 200:
        bad(f"read-back failed (HTTP {status})")
        return False

    seen = [e for e in listing.get("entries", []) if e.get("entry_id") == entry_id]
    if not seen:
        bad("the entry written before the reconnect was not read back")
        return False
    good(f"entry survived the reconnect and reads back ({entry_id})")

    status, verified = fresh.call("GET", "/v1/audit/verify")
    evidence("GET /v1/audit/verify", f"HTTP {status} {json.dumps(verified)}")
    if status != 200 or not verified.get("verified"):
        bad("the chain did not verify after reconnect")
        return False
    good(f"chain verifies after reconnect ({verified.get('entries_checked')} entries)")

    # The part that matters: can this verifier fail? If it cannot, the
    # PASS above is decoration.
    if not db_path:
        print("\n  [~] Tamper control SKIPPED — no SQLite file found.")
        print("      Pass --db /path/to/haldir.db (the one behind the server)")
        print("      to prove the verifier can actually fail.")
        print("\n  Verdict: read-back and verification work across a reconnect.")
        return True

    info(f"Tamper control: editing one row directly in {db_path}")
    applied, original = tamper(db_path, entry_id)
    if not applied:
        bad("could not edit the row — tamper control inconclusive")
        return False
    evidence("edited action to", original + " [edited by haldir_probes.py]")
    evidence("did NOT touch entry_hash", "entry_hash left as originally computed")

    try:
        status, after_tamper = fresh.call("GET", "/v1/audit/verify")
        evidence("verify after tamper", f"HTTP {status} {json.dumps(after_tamper)}")
        if after_tamper.get("verified"):
            bad("the edit went UNDETECTED — the chain does not cover this field")
            return False
        good("the edit was detected")
        evidence("reported error", after_tamper.get("error", "(none)"))
    finally:
        restore(db_path, entry_id, original)

    status, restored = fresh.call("GET", "/v1/audit/verify")
    evidence("verify after restore", f"HTTP {status} {json.dumps(restored)}")
    if not restored.get("verified"):
        bad("the chain did not verify again after restoring the row")
        return False
    good("chain verifies again once the row is restored")

    print("\n  Verdict: read-back and verification survive a reconnect, and")
    print("  the verifier detects an edit made behind its back.")
    return True


# ── Entry point ─────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Three probes against a running Haldir instance.")
    ap.add_argument("--base", default=DEFAULT_BASE,
                    help=f"instance URL (default {DEFAULT_BASE})")
    ap.add_argument("--key", default=os.environ.get("HALDIR_API_KEY"),
                    help="API key; a demo key is minted if omitted")
    ap.add_argument("--db", default=None,
                    help="path to the SQLite file behind the server, "
                         "for probe 3's tamper control")
    args = ap.parse_args()

    c = Client(args.base, args.key)

    info(f"probing {args.base}")
    if not c.api_key:
        status, body = c.call("POST", "/v1/demo/key")
        if status not in (200, 201):
            bad(f"could not mint a demo key (HTTP {status})")
            evidence("response", body)
            print("\n  Is an instance running?  haldir serve")
            return 1
        c.api_key = body.get("key")
        evidence("minted demo key", f"{str(c.api_key)[:12]}...")

    db_path = find_db(args.db)
    results = [
        ("mid-call revocation", probe_mid_call_revocation(c)),
        ("timeout after commit", probe_timeout_after_commit(c)),
        ("audit read-back after reconnect", probe_audit_readback(c, db_path)),
    ]

    banner("Summary")
    for name, passed in results:
        (good if passed else bad)(f"{name}: {'PASS' if passed else 'FAIL'}")

    failed = [n for n, ok in results if not ok]
    if failed:
        print(f"\n  {len(failed)} probe(s) failed. Each printed the raw")
        print("  responses it judged — that is the thing to argue with.")
        return 1
    print("\n  All three passed. If you can make one lie, that is the finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
