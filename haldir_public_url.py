"""
The public origin of this Haldir instance.

Every discovery document Haldir serves — /llms.txt, /sitemap.xml,
/.well-known/agent.json, the OpenAPI spec — names absolute URLs. They were
written against the hosted service, so they say https://haldir.xyz. That is
correct there, and wrong everywhere else.

It matters more here than it would for most software. SELF_HOSTING.md tells
an enterprise to run this themselves, and the audience for those documents
is automated: an agent that reads agent.json and is told to POST to
https://haldir.xyz/v1/sessions will send the customer's credentials and the
customer's data to the vendor's servers. Nothing errors. The request
succeeds. It just succeeds in the wrong place.

The OpenAPI spec had the same problem in a louder form: `servers` pointed at
https://api.haldir.xyz, a hostname with no DNS record. Every client
generated from that spec targeted a name that does not resolve.

So the origin is configuration. Unset, it is the hosted domain and every
response is byte-for-byte what it was before — the deployment that exists
today does not change. Set HALDIR_BASE_URL, and the instance describes
itself instead.

Learn: absolute URLs in generated documents are a self-hosting bug waiting
to happen, and the failure is silent and directional.
"""

from __future__ import annotations

import os

from haldir_logging import get_logger

logger = get_logger(__name__)

# The hosted service. Every served document already contains this string, so
# it is both the default and the thing that gets rewritten.
DEFAULT_PUBLIC_BASE_URL = "https://haldir.xyz"

ENV_VAR = "HALDIR_BASE_URL"

_warned = False


def public_base_url() -> str:
    """Where this instance is reachable from the outside.

    Defaults to the hosted domain, so an unconfigured install behaves
    exactly as it did before this module existed.

    A value without an http(s) scheme is rejected rather than used. It
    would produce documents full of links that are not links, and a
    malformed origin in an agent card is worse than a wrong-but-valid one:
    an agent can retry a 404, but it cannot parse a bare hostname as a URL.
    """
    global _warned

    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        return DEFAULT_PUBLIC_BASE_URL

    if not raw.startswith(("http://", "https://")):
        if not _warned:
            logger.error(
                "%s=%r has no http(s):// scheme; ignoring it and serving %s "
                "instead. Served documents would otherwise contain URLs that "
                "are not parseable as URLs.",
                ENV_VAR, raw, DEFAULT_PUBLIC_BASE_URL,
            )
            _warned = True
        return DEFAULT_PUBLIC_BASE_URL

    return raw.rstrip("/")


def rewrite_public_origin(text: str) -> str:
    """Point the absolute URLs in `text` at this instance.

    Only the full origin is replaced — never the bare domain. "haldir.xyz"
    also appears in this content inside email addresses (sterling@haldir.xyz,
    noreply@haldir.xyz) and inside subdomains (https://api.haldir.xyz).
    Rewriting either would corrupt it: the first produces an address nobody
    can reply to, the second a host that never existed.

    Matching on the scheme makes the replacement exact. "https://haldir.xyz"
    does not occur inside "https://api.haldir.xyz" — that string is
    "https://api." followed by the domain — so subdomains are left alone by
    construction rather than by a rule someone has to remember.

    Returns `text` unchanged when the origin is the default, so the hosted
    service serves its files without touching them.
    """
    base = public_base_url()
    if base == DEFAULT_PUBLIC_BASE_URL:
        return text
    return text.replace(DEFAULT_PUBLIC_BASE_URL, base)
