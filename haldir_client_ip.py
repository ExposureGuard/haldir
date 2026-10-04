"""The client's address, when a trusted edge says what it is.

Why this exists
---------------
Haldir is deployed behind Cloudflare, which fronts a Railway service. The
socket peer the app sees is Railway's internal proxy, and it *rotates* —
production logs show one client arriving from 100.64.0.6, .14, .17 and .22
within a single burst of requests. So `request.remote_addr` is not a client
identity: every per-IP limit keyed on it collapses into a handful of shared
buckets that the whole internet rotates through. A cap meant to be "5 new
accounts per day per address" then protects nobody and randomly refuses
legitimate users.

`X-Forwarded-For` cannot fix that here either. There is no trusted hop to
count from, and on any path that does not come through the edge the header is
caller-supplied, so trusting it is worse than trusting nothing.

The trust model
---------------
The edge — this deployment's Cloudflare Worker, `haldir-apex-proxy` — knows
the client address for certain. Cloudflare rewrites `CF-Connecting-IP` on
every request it handles and refuses client-supplied values (a forged one is
answered 403 at the edge rather than forwarded). The Worker copies that value
into `X-Haldir-Client-IP` and signs the claim with `X-Haldir-Origin-Secret`, a
shared secret that lives in the Worker's environment.

This module trusts the claim only when the secret matches, compared in
constant time. Everything else — including a request that bypasses the Worker
and reaches the Railway hostname directly, where both headers are
caller-supplied — falls back to `remote_addr`, which is exactly the previous
behaviour. A deployment with no secret configured is unaffected: the same
code path, the same address as before.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
from typing import Mapping, Protocol

CLIENT_IP_HEADER = "X-Haldir-Client-IP"
ORIGIN_SECRET_HEADER = "X-Haldir-Origin-Secret"
ORIGIN_SECRET_ENV = "HALDIR_ORIGIN_SECRET"


class _RequestLike(Protocol):
    """What the resolver reads, and all it reads. Flask's request object
    satisfies this; so does the two-line stub the tests use, which is the
    point — identity resolution should not depend on Flask internals."""

    remote_addr: str | None
    headers: Mapping[str, str]


def client_ip(request: _RequestLike) -> str:
    """The best answer available to "whose request is this".

    A trusted-edge claim when one is present, signed and parseable as an IP;
    otherwise the socket peer, exactly as before this module existed.
    """
    secret = os.environ.get(ORIGIN_SECRET_ENV, "")
    if secret:
        presented = request.headers.get(ORIGIN_SECRET_HEADER, "")
        # `presented and` first: compare_digest on two unequal-length strings
        # returns False rather than raising, but an empty presented value
        # against an empty secret would otherwise match, and a secret that is
        # set to "" is not a secret.
        if presented and hmac.compare_digest(presented, secret):
            claimed = (request.headers.get(CLIENT_IP_HEADER) or "").strip()
            if claimed:
                try:
                    return str(ipaddress.ip_address(claimed))
                except ValueError:
                    # A signed claim that is not an address is a bug in the
                    # edge, not a client identity. Fall through rather than
                    # putting arbitrary text into a rate-limit key.
                    pass
    return request.remote_addr or ""
