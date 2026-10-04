"""
OAuth 2.1 for the MCP endpoint, so a connector is added by signing in.

Why this exists
---------------
MCP clients reach a remote server by signing in with a browser. Haldir
authenticates with an API key, so until now the only ways in from Claude were a
beta header field or installing Node to run a bridge. This module implements the
authorization-code flow that turns one button press into an ordinary `hld_` key.

The token it issues **is** an API key, deliberately: `/mcp` and `/v1/*` accept it
unchanged, revocation already works, and no surface needs to learn a second
credential. The cost is that the token is not short-lived and there is no refresh
grant — a knowing deviation from the spec's SHOULD, recorded in THREAT_MODEL.md
rather than glossed.

Read this before changing anything here
---------------------------------------
1. **There is no session and no cookie, on purpose.** The consent POST is
   unauthenticated and its only effect is to create a *new* empty tenant. There is
   no ambient authority to forge, so CSRF adds nothing. Adding a session here
   would *introduce* the ambient authority that makes CSRF possible — a strict
   regression. If a future revision ever adds "sign in to an existing account",
   that revision must add an origin check and a per-form nonce first.

2. **Everything interpolated into the consent page is escaped.** `client_name`
   and `redirect_uri` are attacker-supplied: registration is anonymous, and the
   page is served from the same origin as the dashboard, whose links carry
   `?key=hld_...` in the query string. An unescaped interpolation is a script
   running on haldir.xyz, next to credentials, in a page a reviewer will reach
   from a URL that has one in it.

3. **Redirect URIs are compared, never normalised.** The only relaxation is the
   loopback rule from RFC 8252 §7.3, which exists because a native client picks
   its callback port at runtime. Everything else is exact string equality.

4. **Redemption is one atomic UPDATE.** A SELECT-then-UPDATE double-redeems
   across the two gunicorn workers production runs, and the failure is
   intermittent, which is the worst kind.

5. **Client ID Metadata Documents are not implemented.** They would make this an
   unauthenticated fetcher of arbitrary public URLs on behalf of anyone who asks.
   Claude registers dynamically today; `client_id_metadata_document_supported` is
   advertised as `false` rather than being quietly absent.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from html import escape
from urllib.parse import urlsplit

from haldir_public_url import public_base_url

# ── Constants ────────────────────────────────────────────────────────

# Short enough that a stolen code is stale before it is useful, long enough for
# a browser redirect and a token POST to complete. The spec permits up to 10
# minutes; there is no reason to allow that.
AUTH_CODE_TTL_S = 120

# RFC 8252 §7.3: a native client picks its loopback port at runtime, so the port
# is not part of the identity of a loopback redirect.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Anonymous tenant creation needs a ceiling: every new tenant carries its own
# free allowance, so an uncapped mint is uncapped free capacity. Counted per IP
# per rolling day, from the codes table, because two workers share nothing else.
GRANTS_PER_IP_PER_DAY = 5

# Registrations are cheap and write a row each, so they get a looser ceiling on
# an hourly window — this bounds a loop, it does not gate a person.
REGISTRATIONS_PER_IP_PER_HOUR = 30

MAX_CLIENT_ID_LEN = 2048

# What the token grants. A connector receives the same authority as a Haldir API
# key — the whole point of issuing one — so advertising a narrower scope here
# would be a lie the key itself contradicts.
SCOPE = "*"


class OAuthError(Exception):
    """An error to return in OAuth's own shape: {"error", "error_description"}.

    Deliberately not the API's `{error, code, request_id}` envelope. OAuth
    clients parse this shape, and interop beats internal consistency on a
    protocol endpoint.
    """

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status

    def payload(self) -> dict:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


# ── The issuer, and everything derived from it ───────────────────────
#
# Every absolute URL in this module comes from `issuer()`, never from a literal
# and never from `request.host` — which, with no ProxyFix in front of the app, is
# whatever the caller put in the Host header.

def issuer() -> str:
    return public_base_url().rstrip("/")


def resource() -> str:
    """The canonical URI of the protected resource (RFC 8707)."""
    return issuer() + "/mcp"


def authorization_endpoint() -> str:
    return issuer() + "/oauth/authorize"


def token_endpoint() -> str:
    return issuer() + "/oauth/token"


def registration_endpoint() -> str:
    return issuer() + "/oauth/register"


# ── Discovery documents ──────────────────────────────────────────────
#
# Generated rather than served as files. The repo's other .well-known documents
# are static and rewritten for self-hosted instances; these are derived instead,
# because every URL in them must agree with a route that exists and with the
# `iss` we emit — and a derivation cannot drift from its source the way a
# rewritten string can.

def protected_resource_metadata() -> dict:
    """RFC 9728: what this resource is, and who authorizes it."""
    return {
        "resource": resource(),
        "authorization_servers": [issuer()],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "Haldir",
        "resource_documentation": issuer() + "/docs",
    }


def authorization_server_metadata() -> dict:
    """RFC 8414.

    `code_challenge_methods_supported` is load-bearing beyond documentation: the
    MCP spec says a client that does not find PKCE advertised MUST refuse to
    proceed, so its absence breaks every client rather than degrading.
    """
    return {
        "issuer": issuer(),
        "authorization_endpoint": authorization_endpoint(),
        "token_endpoint": token_endpoint(),
        "registration_endpoint": registration_endpoint(),
        "scopes_supported": [SCOPE],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "authorization_response_iss_parameter_supported": True,
        # Not implemented, and advertised as `false` rather than omitted: a
        # client that sees the flag absent cannot tell "unsupported" from "this
        # server forgot to advertise it".
        #
        # `revocation_endpoint` was here too, as `None`, until an end-to-end
        # check against production read the document back. RFC 8414 defines
        # that field as a URL — `null` is not a value it can hold, so a strict
        # client is entitled to reject the whole document over it. And the
        # reasoning that justifies an explicit `false` above does not transfer:
        # for a URL-typed optional field, *absence* is already the standard way
        # to say "not supported". It is omitted now.
        "client_id_metadata_document_supported": False,
    }


def challenge_header() -> str:
    """The `WWW-Authenticate` value a 401 from /mcp carries.

    This is the whole discovery trigger: a client that gets a bare 401 has no way
    to learn that a sign-in flow exists.
    """
    return (
        f'Bearer resource_metadata="{issuer()}/.well-known/oauth-protected-resource", '
        f'scope="{SCOPE}"'
    )


# ── Redirect URIs ────────────────────────────────────────────────────

def valid_redirect_uri(uri: object) -> bool:
    """Whether a *registered* redirect URI is one we will ever redirect to."""
    if not isinstance(uri, str) or not uri or len(uri) > 2048:
        return False
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https"):
        return False
    if parts.fragment:
        return False
    if not parts.hostname:
        return False
    # A backslash is treated as a path separator by the WHATWG URL parser every
    # browser uses, so `http://evil.example\@localhost/cb` has hostname
    # `localhost` to urlsplit and resolves to evil.example in the browser. The
    # one character is the whole bypass; refuse it outright.
    if "\\" in uri:
        return False
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        return False
    return True


def redirect_uri_matches(registered: list, presented: str) -> bool:
    """Exact match, plus the one relaxation the spec requires.

    Two steps, in this order, and nothing else:

    1. exact string equality against the registered set;
    2. otherwise the loopback rule — http on a loopback host, same path, no
       userinfo — which RFC 8252 §7.3 requires because a native client chooses
       its callback port at runtime. Without it, a client that cannot re-register
       per run can never complete the flow.

    No prefix matching, no `startswith`, no urljoin, no case folding, no
    trailing-slash tolerance. Every one of those has been an open redirect in
    somebody's authorization server.
    """
    if not isinstance(presented, str) or not presented:
        return False
    if presented in registered:
        return True

    p = urlsplit(presented)
    if p.scheme != "http" or p.hostname not in LOOPBACK_HOSTS:
        return False
    if p.username or p.password or p.fragment or "\\" in presented:
        return False
    for reg in registered:
        r = urlsplit(reg)
        if (r.scheme == "http" and r.hostname in LOOPBACK_HOSTS
                and not r.username and not r.password
                and r.path == p.path):
            return True
    return False


def normalize_redirect_uris(raw: object) -> list:
    if not isinstance(raw, list):
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be a list")
    if not raw:
        raise OAuthError("invalid_redirect_uri", "no redirect_uris registered")
    if len(raw) > 8:
        raise OAuthError("invalid_redirect_uri", "too many redirect_uris")
    for uri in raw:
        if not valid_redirect_uri(uri):
            raise OAuthError(
                "invalid_redirect_uri",
                f"{uri!r} is not permitted: https, or http on a loopback address, "
                f"with no fragment",
            )
    return [str(u) for u in raw]


# ── PKCE (RFC 7636) ──────────────────────────────────────────────────

def pkce_challenge_for(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_pkce(code_challenge: str, verifier: object) -> bool:
    """S256 only. `plain` is not accepted, and the verifier's shape is checked
    before it is hashed so a malformed one cannot be smuggled through."""
    if not isinstance(verifier, str):
        return False
    if not 43 <= len(verifier) <= 128:
        return False
    if not all(c.isalnum() or c in "-._~" for c in verifier):
        return False
    return hmac.compare_digest(pkce_challenge_for(verifier), code_challenge)


# ── Clients ──────────────────────────────────────────────────────────

def register_client(conn, *, client_name: str, redirect_uris: list,
                    source: str = "dcr") -> dict:
    """RFC 7591. Anonymous by design — this is how a client gets an id before it
    has any relationship with us, and the id carries no authority: everything it
    can later do requires a human to press a button."""
    client_id = secrets.token_urlsafe(24)
    now = time.time()
    conn.execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, "
        "source, created_at) VALUES (?, ?, ?, ?, ?)",
        (client_id, client_name[:128], json.dumps(redirect_uris), source, now),
    )
    conn.commit()
    return {
        "client_id": client_id,
        "client_name": client_name[:128],
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }


def get_client(conn, client_id: object) -> dict | None:
    if not isinstance(client_id, str) or not client_id or len(client_id) > MAX_CLIENT_ID_LEN:
        return None
    row = conn.execute(
        "SELECT client_id, client_name, redirect_uris FROM oauth_clients "
        "WHERE client_id = ?",
        (client_id,),
    ).fetchone()
    if not row:
        return None
    try:
        uris = json.loads(row["redirect_uris"])
    except (ValueError, TypeError):
        uris = []
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "redirect_uris": uris if isinstance(uris, list) else [],
    }


# ── Authorization codes ──────────────────────────────────────────────

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def hash_ip(ip: str) -> str:
    """A pseudonym for rate limiting, not a record of who visited.

    Unsalted would be reversible by enumerating the IPv4 space, so this is salted
    with a per-deployment value where one exists. It is still a counter key, not
    a secret — but the difference between "a counter" and "a log of addresses"
    is the difference between a limit and a liability.
    """
    salt = os.environ.get("HALDIR_ENCRYPTION_KEY", "")[:32]
    return hashlib.sha256((salt + "|" + (ip or "")).encode()).hexdigest()


def mint_code(conn, *, client_id: str, redirect_uri: str, code_challenge: str,
              tenant_id: str, resource_uri: str, scope: str = SCOPE,
              ip_hash: str = "") -> str:
    code = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, "
        "code_challenge, scope, tenant_id, ip_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (_hash_code(code), client_id, redirect_uri, code_challenge, scope,
         tenant_id, ip_hash, time.time()),
    )
    # Opportunistic cleanup: expired codes are dead weight and this is the only
    # moment we are already writing to the table.
    conn.execute("DELETE FROM oauth_codes WHERE created_at < ?",
                 (time.time() - 3600,))
    conn.commit()
    return code


def redeem_code(conn, *, code: object, client_id: object, redirect_uri: object,
                code_verifier: object) -> dict:
    """Exchange a code for its tenant. Raises OAuthError on every failure path.

    The first statement is an UPDATE guarded on `used_at`, not a SELECT followed
    by one. Two gunicorn workers can service the same code concurrently, and a
    check-then-set pair lets both win — the kind of bug that shows up once in a
    hundred attempts and is blamed on the client.
    """
    if not isinstance(code, str) or not code:
        raise OAuthError("invalid_request", "code is required")

    code_hash = _hash_code(code)
    now = time.time()

    # Claim it. Exactly one caller can see rowcount 1.
    claimed = conn.execute(
        "UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at = 0",
        (now, code_hash),
    ).rowcount
    conn.commit()

    if claimed != 1:
        # Either never existed or already spent. Both are `invalid_grant` to the
        # client; the difference is in the table for whoever investigates.
        raise OAuthError("invalid_grant", "code is invalid or already used")

    row = conn.execute(
        "SELECT client_id, redirect_uri, code_challenge, scope, tenant_id, "
        "created_at FROM oauth_codes WHERE code_hash = ?",
        (code_hash,),
    ).fetchone()

    def refuse(description: str) -> OAuthError:
        # The code is already burned by the claim above, so a wrong verifier
        # cannot be retried against a live code. That is deliberate: an attacker
        # guessing verifiers gets one attempt per code, not a window.
        return OAuthError("invalid_grant", description)

    if row is None:
        raise refuse("code is invalid or already used")
    if now - row["created_at"] > AUTH_CODE_TTL_S:
        raise refuse("code has expired")
    if row["client_id"] != client_id:
        raise refuse("code was issued to a different client")
    if row["redirect_uri"] != redirect_uri:
        raise refuse("redirect_uri does not match the one the code was issued to")
    if not verify_pkce(row["code_challenge"], code_verifier):
        raise refuse("code_verifier does not match the code_challenge")

    return {"tenant_id": row["tenant_id"], "scope": row["scope"] or SCOPE}


def grants_from_ip(conn, ip_hash: str, window_s: int = 86400) -> int:
    if not ip_hash:
        return 0
    row = conn.execute(
        "SELECT COUNT(*) FROM oauth_codes WHERE ip_hash = ? AND created_at > ?",
        (ip_hash, time.time() - window_s),
    ).fetchone()
    return int(row[0]) if row else 0


# ── The consent page ─────────────────────────────────────────────────

def render_consent(*, client: dict, redirect_uri: str, fields: dict,
                   error: str = "") -> str:
    """The one button. A plain form post, so it works without JavaScript.

    Every interpolated value is escaped — see note 2 at the top of this module
    for why that is not optional. The redirect host is shown rather than the whole
    URI because the host is the part a person can actually judge, and it is what
    tells them where their new key is about to be sent.
    """
    host = urlsplit(redirect_uri).hostname or "unknown"
    name = escape(client.get("client_name") or "An application")
    error_block = (
        f'<p class="err">{escape(error)}</p>' if error else ""
    )
    hidden = "".join(
        f'<input type="hidden" name="{escape(k)}" value="{escape(str(v))}">'
        for k, v in fields.items()
    )
    loopback = urlsplit(redirect_uri).hostname in LOOPBACK_HOSTS
    warning = (
        '<p class="warn">This address is on your own machine. That is normal for '
        'a desktop app, and worth a second look if you were not expecting it.</p>'
        if loopback else ""
    )
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connect {name} to Haldir</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#050505;color:#e0ddd5;font-family:'Inter',-apple-system,sans-serif;
padding:3rem 1.5rem;max-width:520px;margin:0 auto}}
h1{{font-weight:200;font-size:1.5rem;letter-spacing:-0.5px;margin-bottom:0.75rem}}
p{{font-size:0.85rem;color:rgba(224,221,213,0.5);line-height:1.8;margin-bottom:1rem}}
.host{{font-family:'IBM Plex Mono',monospace;color:#b8973a;word-break:break-all}}
.card{{border:1px solid rgba(224,221,213,0.08);border-radius:6px;padding:1.75rem;margin:1.5rem 0}}
ul{{list-style:none;font-size:0.85rem;color:rgba(224,221,213,0.5);line-height:2}}
li::before{{content:"· ";color:#b8973a}}
button{{width:100%;padding:0.9rem;border:1px solid #b8973a;background:#b8973a;color:#050505;
font-family:'IBM Plex Mono',monospace;font-size:0.8rem;letter-spacing:1px;border-radius:4px;
cursor:pointer;margin-top:1rem}}
button:hover{{background:transparent;color:#b8973a}}
.err{{color:#e87b7b}} .warn{{color:#e8a33d;font-size:0.78rem}}
</style></head><body>
<h1>Connect {name} to Haldir</h1>
{error_block}
<p>{name} is asking for access. If you continue, it receives a Haldir API key —
the same kind of key you would create yourself — and anything it does with it
lands in your audit trail.</p>
<div class="card">
    <p>Your key will be sent to:</p>
    <p class="host">{escape(host)}</p>
    {warning}
    <ul>
        <li>Scoped sessions, spend limits and approvals apply as normal</li>
        <li>Every action is written to a hash-chained audit log</li>
        <li>You can revoke the key at any time, from the dashboard or the CLI</li>
        <li>No password, email or card is involved</li>
    </ul>
</div>
<form method="post" action="/oauth/authorize">
    {hidden}
    <button type="submit">Create a key and connect</button>
</form>
<p style="margin-top:1.5rem;font-size:0.75rem">Not expecting this? Close the
tab — nothing has been created yet.</p>
</body></html>"""


def render_error_page(error: str, description: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Haldir — authorization error</title></head>
<body style="background:#050505;color:#e0ddd5;font-family:sans-serif;padding:3rem;max-width:520px;margin:0 auto">
<h1 style="font-weight:200">That did not work</h1>
<p style="color:rgba(224,221,213,0.5);line-height:1.8">{escape(description)}</p>
<p style="color:rgba(224,221,213,0.3);font-family:monospace;font-size:0.75rem">{escape(error)}</p>
<p style="color:rgba(224,221,213,0.5);font-size:0.85rem">Nothing was created. Try
again from the client, or email <a href="mailto:hello@haldir.xyz" style="color:#b8973a">hello@haldir.xyz</a>.</p>
</body></html>"""
