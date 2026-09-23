"""
Safety for URLs Haldir fetches on a user's behalf.

Haldir makes outbound requests to addresses its users choose: webhook
endpoints, approval notification targets. Two places did that with a bare
`urllib.request.urlopen(wh.url)` and no check on the URL at all.

That is a local file disclosure and an SSRF in one line. `urlopen` honours
whatever scheme it is handed:

    urllib.request.urlopen("file:///etc/passwd").read()
    -> b'root:x:0:0:root:/root:/bin/bash\\n...'

The body is read back into `response_excerpt`, written to the webhook
delivery record, and served over the API — so registering a webhook with
`url = "file:///etc/shadow"` and firing any event reads the file out. The
same call reaches `http://169.254.169.254/latest/meta-data/iam/…` on a cloud
instance, and any internal service the host can route to.

`safe_outbound_url` refuses anything that is not plain http(s) to a public
address, and is called both when a URL is registered and again when it is
used — because a name that resolved to a public address at registration can
resolve to 127.0.0.1 by the time it is fetched.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import NoReturn
from urllib.parse import urlsplit

# Schemes Haldir will fetch. Deliberately a list of two and not a blocklist:
# urllib also speaks ftp, file, and whatever a handler has been registered
# for, and enumerating what to forbid loses that race.
#
# Never relaxed, by any setting. There is no deployment in which fetching
# `file://` on a user's behalf is the intended behaviour, and this is the
# check that closes the file disclosure.
ALLOWED_SCHEMES = ("http", "https")

# Opt-out for the address check only, for self-hosted deployments.
#
# On the hosted service an outbound URL is attacker-controlled: any tenant can
# register a webhook or a proxy upstream, so neither may reach the metadata
# endpoint or the internal network. Self-hosted is the other way round — the
# operator owns both ends, and pointing a webhook at an internal service (a
# Slack relay, a ticketing bridge, something on the private subnet) is a
# normal thing to want. Refusing it by default there would be security
# theatre that pushes people to disable the check entirely.
#
# Set HALDIR_ALLOW_PRIVATE_OUTBOUND=1 to permit private addresses. It does
# not relax the scheme check.
ALLOW_PRIVATE_ENV = "HALDIR_ALLOW_PRIVATE_OUTBOUND"

# The name this shipped under, when webhooks were the only caller.
#
# It is accepted as an alias rather than kept as a parallel setting: the
# proxy needs the same opt-out for the same reason, and two switches for one
# decision is how a deployment ends up with the check relaxed in one place
# and enforced in the other.
ALLOW_PRIVATE_ENV_LEGACY = "HALDIR_ALLOW_PRIVATE_WEBHOOKS"


class UnsafeURL(ValueError):
    """A URL Haldir refuses to fetch on a user's behalf."""


def _private_allowed() -> bool:
    on = ("1", "true", "yes", "on")
    return any(
        os.environ.get(var, "").strip().lower() in on
        for var in (ALLOW_PRIVATE_ENV, ALLOW_PRIVATE_ENV_LEGACY)
    )


# NoReturn, not None: mypy narrows `if not host: _reject(...)` to treat
# host as str afterwards only if it knows this never returns.
def _reject(reason: str, url: str) -> NoReturn:
    raise UnsafeURL(f"{reason}: {url!r}")


def _check_address(host: str, port: int, url: str) -> None:
    """Resolve `host` and refuse if any answer is not a public address.

    Every answer is checked, not just the first: a name may resolve to both a
    public address and a loopback one, and urllib will use whichever it
    reaches first. `getaddrinfo` is asked for both families so an AAAA-only
    route to ::1 is caught as well as an A record to 127.0.0.1.
    """
    if _private_allowed():
        return  # operator has opted in; scheme and credentials still checked

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeURL(f"host {host!r} does not resolve ({e})") from e

    if not infos:
        _reject("host does not resolve", url)

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            _reject(f"unparseable address {addr!r}", url)

        # The full set matters. `is_private` covers RFC1918 and loopback, but
        # link-local — which is where 169.254.169.254 lives, the cloud
        # metadata endpoint that hands out instance credentials — is its own
        # flag, and so are reserved and multicast.
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            _reject(
                f"host {host!r} resolves to {addr}, which is not a public "
                f"address",
                url,
            )


def safe_outbound_url(url: str) -> str:
    """Return `url` if Haldir may fetch it, else raise UnsafeURL.

    Checks, in order: it parses, the scheme is http or https, it carries no
    credentials, it names a host, and every address that host resolves to is
    public. The port is not restricted — webhook receivers legitimately run on
    non-standard ports, and the address check is what actually bounds where
    the request can go.

    Not a complete SSRF defence on its own: it cannot stop a name resolving
    public now and private a moment later. That is why callers check at
    delivery time as well as at registration.

    The address half is skipped entirely when HALDIR_ALLOW_PRIVATE_OUTBOUND
    (or the older HALDIR_ALLOW_PRIVATE_WEBHOOKS) is set — see the note on
    that constant. The scheme and credential checks are not, so a
    self-hosted deployment can still not be talked into reading a file.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeURL("webhook URL is empty")

    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise UnsafeURL(f"could not parse URL {url!r}: {e}") from e

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        _reject(
            f"scheme {parts.scheme!r} is not allowed (http and https only)",
            url,
        )

    if parts.username or parts.password:
        # Credentials in the URL would be replayed on every delivery and
        # stored in the webhook row in clear text.
        _reject("URL must not embed credentials", url)

    host = parts.hostname
    if not host:
        _reject("URL has no host", url)

    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as e:
        raise UnsafeURL(f"invalid port in {url!r}: {e}") from e

    _check_address(host, port, url)
    return url
