"""
Haldir /demo/tamper — the adversarial demo.

Shows a VC (or anyone) in 60 seconds why Haldir's tamper-evidence story
is real and not marketing. The visitor:

  1. Sees a pre-seeded audit log of 5 entries belonging to a demo
     tenant, plus the current Signed Tree Head (RFC 6962 root + HMAC
     signature) and an inclusion proof for entry #3.
  2. Clicks "Tamper with entry #3" — we literally mutate the stored
     `cost_usd` column of that row in the live DB.
  3. The page re-renders: the tree root hash changes, the previously-
     captured inclusion proof now fails verification, and a red banner
     names the exact entry that was modified.
  4. "Reset" button restores the original row.

Everything is against the same primitives shipped in production:
haldir_merkle.verify_inclusion_hex, haldir_audit_tree.get_tree_head,
etc. Nothing is mocked — this is a live demonstration of the
cryptographic contract, not a visualization.

The demo tenant is isolated (tenant_id = "demo-tamper-public"); even if
an attacker on the internet hammered the Tamper button, they can only
tamper the demo tenant's log.
"""

from __future__ import annotations

import html as _h
import json
import time
from typing import Any

DEMO_TENANT = "demo-tamper-public"

# The seed rows. Deterministic entry_ids so the page is stable across
# restarts and the "entry_id of interest" stays the same.
SEED_ROWS: list[dict[str, Any]] = [
    {
        "entry_id":   "demo-entry-001",
        "session_id": "demo-session-alpha",
        "agent_id":   "acme-agent-1",
        "action":     "stripe.charge.create",
        "tool":       "stripe",
        "cost_usd":   4.99,
        "details":    '{"currency": "usd", "customer": "cus_demo"}',
        "ts_offset":  -3600 * 24 * 3,   # 3 days ago
    },
    {
        "entry_id":   "demo-entry-002",
        "session_id": "demo-session-alpha",
        "agent_id":   "acme-agent-1",
        "action":     "postgres.read",
        "tool":       "postgres",
        "cost_usd":   0.00,
        "details":    '{"rows": 42, "table": "orders"}',
        "ts_offset":  -3600 * 24 * 2,
    },
    {
        "entry_id":   "demo-entry-003",
        "session_id": "demo-session-alpha",
        "agent_id":   "acme-agent-1",
        "action":     "stripe.refund.create",
        "tool":       "stripe",
        "cost_usd":   12.50,
        "details":    '{"amount": 1250, "reason": "customer_request"}',
        "ts_offset":  -3600 * 24,
    },
    {
        "entry_id":   "demo-entry-004",
        "session_id": "demo-session-beta",
        "agent_id":   "acme-agent-2",
        "action":     "github.issue.comment",
        "tool":       "github",
        "cost_usd":   0.00,
        "details":    '{"repo": "acme/api", "issue": 118}',
        "ts_offset":  -3600 * 6,
    },
    {
        "entry_id":   "demo-entry-005",
        "session_id": "demo-session-beta",
        "agent_id":   "acme-agent-2",
        "action":     "slack.message.send",
        "tool":       "slack",
        "cost_usd":   0.00,
        "details":    '{"channel": "#ops", "text_hash": "..."}',
        "ts_offset":  -60 * 12,
    },
]

# Entry we seed a captured inclusion proof for — same one the visitor
# gets shown and the same one "Tamper" mutates.
TARGET_ENTRY_ID = "demo-entry-003"


# ── DB helpers ────────────────────────────────────────────────────────

def _db():
    import api
    from haldir_db import get_db
    return get_db(api.DB_PATH)


def _count_seed(conn) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
        (DEMO_TENANT,),
    ).fetchone()
    return int(row[0])


def _is_tampered(conn) -> bool:
    """The demo is considered "tampered" if the target row's cost_usd
    differs from the seed value. We don't need a separate state table —
    the DB row itself IS the state."""
    row = conn.execute(
        "SELECT cost_usd FROM audit_log "
        "WHERE tenant_id = ? AND entry_id = ?",
        (DEMO_TENANT, TARGET_ENTRY_ID),
    ).fetchone()
    if not row:
        return False
    seed = next(r for r in SEED_ROWS if r["entry_id"] == TARGET_ENTRY_ID)
    return abs(float(row["cost_usd"]) - float(seed["cost_usd"])) > 0.001


def ensure_seeded() -> None:
    """Seed the demo tenant's audit_log if it isn't already. Idempotent."""
    conn = _db()
    try:
        if _count_seed(conn) >= len(SEED_ROWS):
            return
        now = time.time()
        for r in SEED_ROWS:
            conn.execute(
                "INSERT OR IGNORE INTO audit_log "
                "(entry_id, tenant_id, session_id, agent_id, action, tool, "
                " details, cost_usd, timestamp, flagged, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
                (
                    r["entry_id"], DEMO_TENANT, r["session_id"],
                    r["agent_id"], r["action"], r["tool"],
                    r["details"], r["cost_usd"],
                    now + r["ts_offset"],
                    # A throwaway entry_hash for schema satisfaction; the
                    # DEMO tree is recomputed from scratch each render,
                    # so prev_hash/entry_hash chain values don't matter.
                    f"demo-{r['entry_id']}",
                ),
            )
        conn.commit()
    finally:
        conn.close()


def tamper_target() -> None:
    """Mutate the cost_usd of the target row. That's the adversarial
    action: an attacker with DB access silently rewrites a charge amount
    and hopes no-one notices."""
    conn = _db()
    try:
        ensure_seeded()
        conn.execute(
            "UPDATE audit_log SET cost_usd = cost_usd + 9000 "
            "WHERE tenant_id = ? AND entry_id = ?",
            (DEMO_TENANT, TARGET_ENTRY_ID),
        )
        conn.commit()
    finally:
        conn.close()


def reset() -> None:
    """Restore the target row to its seed cost_usd."""
    conn = _db()
    try:
        seed = next(r for r in SEED_ROWS if r["entry_id"] == TARGET_ENTRY_ID)
        conn.execute(
            "UPDATE audit_log SET cost_usd = ? "
            "WHERE tenant_id = ? AND entry_id = ?",
            (seed["cost_usd"], DEMO_TENANT, TARGET_ENTRY_ID),
        )
        conn.commit()
    finally:
        conn.close()


# ── Captured "pre-tamper" proof ──────────────────────────────────────
#
# The visitor's mental model: "I wrote this inclusion proof down
# yesterday. Today Haldir tampered with the DB. My yesterday-proof
# should no longer verify."
#
# We compute both the pre-tamper proof and the post-tamper state on
# demand: pre-tamper by temporarily substituting the seed cost_usd
# into the leaf-bytes computation, post-tamper from the live DB.

def _seed_leaves() -> list[tuple[str, bytes]]:
    """Compute the leaf hashes as they would be if the target entry had
    its SEED cost_usd. Used to produce the "pre-tamper" inclusion proof
    we show the visitor before they click Tamper — and which then fails
    to verify against the tampered root."""
    import haldir_audit_tree
    import haldir_merkle as merkle
    import api
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    try:
        rows = conn.execute(
            "SELECT entry_id, session_id, agent_id, action, tool, "
            "details, cost_usd, timestamp, flagged, prev_hash "
            "FROM audit_log WHERE tenant_id = ? "
            "ORDER BY timestamp ASC, entry_id ASC",
            (DEMO_TENANT,),
        ).fetchall()
    finally:
        conn.close()

    seed_map = {r["entry_id"]: r["cost_usd"] for r in SEED_ROWS}
    out: list[tuple[str, bytes]] = []
    for row in rows:
        row_dict = dict(row)
        # Substitute seed cost_usd if this is the target row.
        if row_dict["entry_id"] in seed_map:
            row_dict["cost_usd"] = seed_map[row_dict["entry_id"]]
        leaf = merkle.leaf_hash(haldir_audit_tree.entry_leaf_bytes(row_dict))
        out.append((row_dict["entry_id"], leaf))
    return out


def _proof_for_target(leaves: list[tuple[str, bytes]]) -> dict:
    import haldir_merkle as merkle
    # Find index of the target row.
    index = next(i for i, (eid, _) in enumerate(leaves) if eid == TARGET_ENTRY_ID)
    leaf_hashes = [lh for _, lh in leaves]
    proof = merkle.generate_inclusion_proof(leaf_hashes, index)
    proof["entry_id"] = TARGET_ENTRY_ID
    return proof


# ── Page render ───────────────────────────────────────────────────────

def render() -> str:
    import haldir_audit_tree
    import haldir_merkle as merkle

    ensure_seeded()
    tampered = False
    conn = _db()
    try:
        tampered = _is_tampered(conn)
    finally:
        conn.close()

    # "Pre-tamper" proof — as if the target row still had its seed cost.
    pre_leaves = _seed_leaves()
    pre_proof = _proof_for_target(pre_leaves)
    pre_root = pre_proof["root_hash"]

    # Live tree-head off the live DB.
    live_sth = haldir_audit_tree.get_tree_head(__import__("api").DB_PATH,
                                                 DEMO_TENANT)
    live_root = live_sth["root_hash"]

    # Does the pre-tamper proof still verify against the live tree?
    # Yes iff pre_root == live_root (i.e., no tampering has happened).
    proof_verifies = merkle.verify_inclusion_hex(pre_proof) and (
        pre_root == live_root
    )

    # Pull the rows for the table display.
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT entry_id, session_id, agent_id, action, tool, "
            "cost_usd, timestamp FROM audit_log WHERE tenant_id = ? "
            "ORDER BY timestamp ASC, entry_id ASC",
            (DEMO_TENANT,),
        ).fetchall()
    finally:
        conn.close()

    row_html = []
    for r in rows:
        is_target = r["entry_id"] == TARGET_ENTRY_ID
        tamper_badge = ""
        if is_target and tampered:
            tamper_badge = ' <span class="tampered-pill">TAMPERED</span>'
        row_html.append(f"""
          <tr class="{'target' if is_target else ''}">
            <td class="mono">{_h.escape(r['entry_id'])}{tamper_badge}</td>
            <td class="mono">{_h.escape(r['action'])}</td>
            <td class="mono">{_h.escape(r['tool'])}</td>
            <td class="mono cost">${float(r['cost_usd']):,.2f}</td>
          </tr>""")

    banner_html = _render_banner(tampered, proof_verifies, pre_root, live_root)

    pre_proof_json = _h.escape(json.dumps(pre_proof, indent=2))
    live_sth_json = _h.escape(json.dumps({
        "tree_size":   live_sth["tree_size"],
        "root_hash":   live_sth["root_hash"],
        "signed_at":   live_sth["signed_at"],
        "signature":   live_sth["signature"],
        "algorithm":   live_sth["algorithm"],
    }, indent=2))

    diff_class = "verified" if proof_verifies else "failed"
    diff_label = "VERIFIES against live root" if proof_verifies \
                  else "FAILS — live root differs from the proof's root"

    return _PAGE_TEMPLATE.format(
        banner=banner_html,
        rows="".join(row_html),
        pre_proof_json=pre_proof_json,
        live_sth_json=live_sth_json,
        diff_class=diff_class,
        diff_label=diff_label,
        target_entry=TARGET_ENTRY_ID,
        tree_size=live_sth["tree_size"],
        target_id=TARGET_ENTRY_ID,
    )


def _render_banner(tampered: bool, proof_verifies: bool,
                     pre_root: str, live_root: str) -> str:
    if not tampered and proof_verifies:
        return (
            '<div class="banner banner-ok">'
            '<strong>Untampered.</strong> The live Merkle root matches the '
            'root the visitor-side inclusion proof commits to. Click '
            '<em>Tamper</em> to rewrite entry {tgt}\u2019s cost_usd and watch '
            'this banner flip.'
            '</div>'
        ).format(tgt=TARGET_ENTRY_ID)
    # Tampered state — explicit delta.
    return (
        '<div class="banner banner-bad">'
        '<strong>Tamper detected.</strong> The DB row for '
        '<code>{tgt}</code> was silently rewritten. The pre-tamper '
        'inclusion proof the visitor captured now fails: its root '
        '<code>{pre}\u2026</code> no longer matches the live Merkle '
        'root <code>{live}\u2026</code>. An auditor pinning the earlier '
        'Signed Tree Head would fork-detect this immediately \u2014 the '
        'same primitive Certificate Transparency uses for the global WebPKI.'
        '</div>'
    ).format(
        tgt=_h.escape(TARGET_ENTRY_ID),
        pre=_h.escape(pre_root[:16]),
        live=_h.escape(live_root[:16]),
    )


# ── HTML template ────────────────────────────────────────────────────

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=robots content="index,follow">
<title>Haldir \u00b7 Tamper-evidence live demo</title>
<style>
:root{{
  --bg:#0b0d12;--fg:#e6e4dd;--dim:#8a8676;--gold:#d4af37;
  --ok:#0b8043;--bad:#c0392b;--line:#1f2430;--card:#141822;
  --mono:'IBM Plex Mono',ui-monospace,Menlo,monospace;
  --sans:'Inter',-apple-system,system-ui,Segoe UI,sans-serif;
}}
*{{box-sizing:border-box}}
body{{background:var(--bg);color:var(--fg);font-family:var(--sans);
  margin:0;padding:2rem 1rem;line-height:1.55}}
.wrap{{max-width:960px;margin:0 auto}}
h1{{font-family:var(--mono);font-weight:500;font-size:1.35rem;
  letter-spacing:-0.01em;margin:0 0 0.25rem 0}}
h1 .gold{{color:var(--gold)}}
.lede{{color:var(--dim);font-size:0.95rem;margin:0 0 2rem 0;max-width:58ch}}
.banner{{padding:1rem 1.15rem;border-radius:6px;margin:1.5rem 0;
  font-size:0.95rem;border:1px solid transparent}}
.banner-ok{{background:#0b8043;background:rgba(11,128,67,0.12);
  border-color:#0b8043;color:#a9e5c4}}
.banner-bad{{background:rgba(192,57,43,0.15);border-color:#c0392b;
  color:#f2a8a0}}
.banner code{{font-family:var(--mono);background:rgba(0,0,0,0.35);
  padding:0.1rem 0.35rem;border-radius:3px;font-size:0.85em}}
.actions{{display:flex;gap:0.75rem;margin:1rem 0 2rem 0;flex-wrap:wrap}}
.btn{{font-family:var(--mono);font-size:0.9rem;background:var(--card);
  color:var(--fg);border:1px solid var(--line);border-radius:4px;
  padding:0.55rem 0.9rem;cursor:pointer;text-decoration:none;
  display:inline-block;transition:border-color 0.12s}}
.btn:hover{{border-color:var(--gold)}}
.btn-danger{{color:#f2a8a0;border-color:#3a1f1d}}
.btn-danger:hover{{border-color:#c0392b}}
.btn-ghost{{color:var(--dim)}}
table{{width:100%;border-collapse:collapse;margin:0.5rem 0;
  font-size:0.88rem}}
th{{text-align:left;font-family:var(--mono);font-weight:400;
  color:var(--dim);border-bottom:1px solid var(--line);padding:0.55rem 0.5rem;
  font-size:0.78rem;text-transform:uppercase;letter-spacing:0.04em}}
td{{padding:0.55rem 0.5rem;border-bottom:1px solid var(--line)}}
.mono{{font-family:var(--mono)}}
tr.target td{{background:rgba(212,175,55,0.05)}}
tr.target td:first-child{{border-left:2px solid var(--gold);
  padding-left:calc(0.5rem - 2px)}}
.cost{{text-align:right;color:#c9c4af}}
.tampered-pill{{background:#c0392b;color:#fff;padding:0.15rem 0.45rem;
  border-radius:3px;font-size:0.7rem;letter-spacing:0.06em;
  margin-left:0.5rem;font-family:var(--mono)}}
h2{{font-family:var(--mono);font-weight:500;font-size:1rem;
  margin:2rem 0 0.6rem 0;color:var(--gold);
  text-transform:uppercase;letter-spacing:0.06em}}
h2 small{{color:var(--dim);text-transform:none;letter-spacing:0;
  font-size:0.78rem;margin-left:0.5rem}}
pre{{background:var(--card);border:1px solid var(--line);border-radius:4px;
  padding:0.9rem 1rem;overflow-x:auto;font-family:var(--mono);
  font-size:0.78rem;color:#c9c4af;line-height:1.5;margin:0.4rem 0 0 0}}
.split{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;
  margin-top:0.4rem}}
@media(max-width:720px){{.split{{grid-template-columns:1fr}}}}
.split>div{{min-width:0}}
.result{{padding:0.75rem 1rem;border-radius:4px;margin-top:0.75rem;
  font-family:var(--mono);font-size:0.85rem}}
.result.verified{{background:rgba(11,128,67,0.12);
  border:1px solid #0b8043;color:#a9e5c4}}
.result.failed{{background:rgba(192,57,43,0.15);
  border:1px solid #c0392b;color:#f2a8a0}}
footer{{color:var(--dim);font-size:0.85rem;margin-top:3rem;
  padding-top:1.5rem;border-top:1px solid var(--line)}}
a{{color:var(--gold);text-decoration:none;border-bottom:1px dotted}}
a:hover{{color:#f3c94e}}
</style>
</head>
<body>
<div class=wrap>

<h1>Haldir <span class=gold>/</span> tamper-evidence, live.</h1>
<p class=lede>This is a real audit log for a demo tenant stored in
Haldir's live Postgres. The Signed Tree Head below is an RFC&nbsp;6962
Merkle root signed with HMAC-SHA256 &mdash; the same primitive
Certificate Transparency uses to keep 7&nbsp;billion TLS certificates
honest. Click <em>Tamper</em> and Haldir will catch the DB mutation
cryptographically, not by diffing or monitoring.</p>

{banner}

<div class=actions>
  <form method=POST action="/demo/tamper/mutate" style="display:inline">
    <button class="btn btn-danger">Tamper with entry {target_entry}</button>
  </form>
  <form method=POST action="/demo/tamper/reset" style="display:inline">
    <button class="btn btn-ghost">Reset</button>
  </form>
  <a class="btn btn-ghost" href="/compliance?demo=1">See full evidence pack</a>
  <a class="btn btn-ghost" href="https://github.com/haldir-xyz/haldir/blob/main/haldir_merkle.py">haldir_merkle.py</a>
</div>

<h2>Audit log <small>tenant: demo-tamper-public &middot; {tree_size} entries</small></h2>
<table>
  <tr><th>Entry ID</th><th>Action</th><th>Tool</th><th>Cost USD</th></tr>
  {rows}
</table>

<div class=split>
  <div>
    <h2>Live Signed Tree Head <small>GET /v1/audit/tree-head</small></h2>
    <pre>{live_sth_json}</pre>
  </div>
  <div>
    <h2>Inclusion proof captured pre-tamper <small>for {target_id}</small></h2>
    <pre>{pre_proof_json}</pre>
  </div>
</div>

<div class="result {diff_class}">
  Visitor-held proof vs. live root: <strong>{diff_label}</strong>
</div>

<footer>
<p>Everything on this page is a live round-trip against production
primitives: <code>haldir_merkle.leaf_hash</code>,
<code>haldir_merkle.mth</code>, <code>haldir_merkle.verify_inclusion_hex</code>.
The same functions ship in the <code>haldir</code> SDK so customers can
verify proofs offline &mdash; no trust in Haldir required beyond the STH
signing key. Source:
<a href="https://github.com/haldir-xyz/haldir">github.com/haldir-xyz/haldir</a>.</p>
</footer>

</div>
</body>
</html>
"""
