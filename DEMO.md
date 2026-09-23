# Trying Haldir

Three ways in, smallest first. All of them run a real instance on your own
machine — there is nothing simulated, no signup, and no account.

- [The one-file demo](#the-one-file-demo) — no Python, no install
- [If you have Python](#if-you-have-python) — `pip install haldir`
- [What the three probes prove](#what-the-three-probes-prove)
- [Poking at it](#poking-at-it)
- [What's in the browser](#whats-in-the-browser)
- [Known limits](#known-limits)

---

## The one-file demo

A single 34 MB binary with Python and Haldir inside it. Linux x86-64.

```bash
curl -LO https://github.com/ExposureGuard/haldir/releases/download/demo-preview-1/haldir-demo
chmod +x haldir-demo
./haldir-demo
```

It starts a throwaway instance on a free port, runs three probes against it,
prints the raw responses behind each verdict, and deletes everything it made.
About twenty seconds. **Exit code is 0 only if all three probes passed.**

Then, to actually use it:

```bash
./haldir-demo --keep
```

Same setup, but the instance stays up and it prints:

- the demo URLs (in-browser and tamper)
- **a working API key**
- copy-paste `curl` commands that work as pasted
- the Python equivalent

Ctrl-C stops it and removes everything, including the data directory.

---

## If you have Python

Python 3.10 or newer, nothing else:

```bash
pip install haldir
haldir serve
```

`haldir serve` prints a URL and an API key, and the CLI is pointed at that
instance automatically. That is the full product — the API, the dashboard, the
demo pages, the CLI — with no Docker and no Postgres.

Use `--data-dir ~/my-haldir` if you want the data to survive between runs;
otherwise it lives in `~/.haldir`.

**Then run the same three probes**, which ship inside the package:

```bash
python3 -m haldir_probes --serve
```

That starts its own disposable instance, so you can run it without `haldir
serve` already running. To probe an instance you already have:

```bash
python3 -m haldir_probes              # against http://127.0.0.1:8000
```

### From a checkout instead

`demo_quickstart.py` is the one-file version — it bootstraps a throwaway
virtualenv, installs Haldir into it, and deletes it afterwards:

```bash
python3 demo_quickstart.py            # the probes
python3 demo_quickstart.py --keep     # leave it up, print the key
python3 demo_quickstart.py --from ./haldir-0.4.0-py3-none-any.whl
```

---

## What the three probes prove

These are the three things a reviewer of this project said they would attack
first. Each is built so that it **can fail** — a check that cannot fail is not
evidence, so every probe carries a control.

### 1. Mid-call revocation

*Is revocation enforced on every call, or cached when the session was created?*

Creates a session, confirms a granted scope is allowed, revokes it, and asks
again. It also asks for a scope that was **never granted**, first, as a control
— otherwise a gate that simply always answers "no" would pass.

```
[*] scope 'delete' (never granted) before revocation -> False
[+] never-granted scope correctly denied (control)
[*] scope 'read' (granted) before revocation -> True
[+] granted scope allowed before revocation
[+] session revoked
[*] scope 'read' after revocation -> False
[+] revoked session denied on the next call
```

### 2. Timeout after commit

*A client POSTs, the server commits, the response is lost in flight. The client
retries. Does the server do the work twice?*

Sends one `Idempotency-Key` twice and confirms the second call returns the
**original** response without a second audit entry. Then it reuses that key with
a **different body** and requires a 422 — because a key that silently accepts a
different body is not idempotency.

### 3. Audit read-back after reconnect

*A fresh connection reads back what a previous client wrote, and verifies it.*

Then the part that matters: it edits one row in the SQLite file **behind the
server's back**, without touching the stored hash, and requires verification to
**fail**. Then it restores the row and requires it to pass again.

```
[+] chain verifies after reconnect (2 entries)
[*] Tamper control: editing one row directly in .../haldir.db
      verify after tamper: {"error": "Entry hash mismatch — data was modified",
                            "verified": false}
[+] the edit was detected
[+] chain verifies again once the row is restored
```

Without that direction, `"verified": true` proves nothing. **This probe needs
the database file**, so it works against a local instance — not a hosted one.

---

## Poking at it

The instance is real, so point whatever you like at it. `--keep` prints these
with the values filled in:

```bash
export HALDIR_BASE_URL=http://127.0.0.1:<port>
export HALDIR_API_KEY=hld_...

# open a governed session
curl -s -X POST $HALDIR_BASE_URL/v1/sessions \
  -H "Authorization: Bearer $HALDIR_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"my-agent","scopes":["read","execute"],"spend_limit":5.00}'

# spend past the cap — expect 403
curl -s -X POST $HALDIR_BASE_URL/v1/payments/authorize \
  -H "Authorization: Bearer $HALDIR_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"ses_...","amount":10.00}'

# has anything been edited since it was written?
curl -s $HALDIR_BASE_URL/v1/audit/verify -H "Authorization: Bearer $HALDIR_API_KEY"
```

Or from Python:

```python
from haldir import HaldirClient
h = HaldirClient(api_key="hld_...", base_url="http://127.0.0.1:<port>")

session = h.create_session("my-agent", scopes=["read", "execute"], spend_limit=5.00)
h.check_permission(session["session_id"], "execute")
h.log_action(session["session_id"], "stripe", "charge", 0.50)
```

The full reference is at `/docs` and `/openapi.json` on the instance.

---

## What's in the browser

At the URL `haldir serve` prints.

| | |
|---|---|
| **`/demo`** | Four steps walk the happy path, then **three try to break it**: spend past the cap (403), revoke the session mid-flight, and act after revocation — denied on the same session ID that was allowed a second earlier. Step 03 lets you pick a scope that was never granted, so you can see a denial as well as an approval. |
| **`/demo/tamper`** | Rewrite an audit entry and watch the hash chain catch it. The same Merkle code the API ships. |
| **`/admin/overview`** | The monitoring console: sessions, spend against cap, live activity, and a Revoke button that cascades to subagents. |
| **`/gallery`** | Every screenshot in the README, in one place. |

---

## Known limits

- **The demo binary is Linux x86-64.** On macOS or Windows it will not run —
  use `pip install haldir` and `python3 -m haldir_probes --serve`, which work
  anywhere Python does.
- **The free tier is one agent and 10,000 API calls a month.** "Agent limit
  reached" is the tier, not a bug.
- **It binds `127.0.0.1` only.** Nothing leaves your machine.
- **The demo key endpoint (`POST /v1/demo/key`) is unauthenticated** and mints a
  sandbox tenant per call. That is what makes the in-browser demo work with no
  signup; it is worth knowing if you expose an instance publicly.

---

## If a probe fails

That is a finding, not a broken demo. Each probe prints the raw responses it
based its verdict on, so the failure can be checked by hand rather than taken on
faith — that is the point of the fixture.

The audit chain, the idempotency store and the session store are the three
areas these cover. If you can make one of them lie, that is exactly what we want
to hear about.
