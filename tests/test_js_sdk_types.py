"""
The JavaScript SDK's types must describe the JavaScript SDK.

`index.d.ts` is what a TypeScript consumer sees, and nothing compared it to
`index.js`. Eight methods were implemented and documented in the README but
never declared — `requestApproval`, `getApproval`, `approveRequest`,
`denyRequest`, `listPendingApprovals`, `createWebhook`, `listWebhooks` and
`getUsage`. The entire human-in-the-loop path was invisible to the type
checker, which is the audience the declaration file exists for.

Checked by reading both files rather than by running `tsc`, so it runs in the
Python suite alongside everything else and needs no Node toolchain in CI.

Run: python -m pytest tests/test_js_sdk_types.py -v
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(ROOT, "sdk-js", "index.js")
DTS = os.path.join(ROOT, "sdk-js", "index.d.ts")


def _class_body(path: str, opener: str) -> str:
    """The text of the `Client` class, from its opening line to the brace
    that closes it at column 0."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    start = src.find(opener)
    assert start >= 0, f"{os.path.basename(path)} has no {opener!r}"
    body = src[start:]
    end = body.find("\n}")
    return body[: end if end >= 0 else len(body)]


def _names_from(body: str) -> set[str]:
    """Method names declared at the class's own indentation — exactly two
    spaces.

    Anchoring on the exact indent matters: a looser `^\\s+` also matches calls
    inside a method body, so `clearTimeout(timer)` six spaces deep was read as
    a method and reported as undeclared. Leading-underscore names are private
    by convention and deliberately not part of the published surface.
    """
    names = set(re.findall(r"^  (?:async )?([a-zA-Z_$][\w$]*)\s*\(", body, re.M))
    return {n for n in names if not n.startswith("_")} - {"constructor"}


def _implemented() -> set[str]:
    return _names_from(_class_body(JS, "class Client {"))


def _declared() -> set[str]:
    return _names_from(_class_body(DTS, "export class Client {"))


def test_every_implemented_method_is_declared() -> None:
    implemented, declared = _implemented(), _declared()
    assert implemented, "parsed no methods from index.js — this scan has stopped matching"
    assert declared, "parsed no declarations from index.d.ts — same"

    undeclared = sorted(implemented - declared)
    assert not undeclared, (
        f"these methods exist on the JS client but are not declared in "
        f"index.d.ts, so a TypeScript consumer cannot call them: {undeclared}"
    )


def test_no_declaration_describes_a_method_that_does_not_exist() -> None:
    """The other direction: a declaration with no implementation is a method
    that type-checks and then fails at runtime."""
    orphaned = sorted(_declared() - _implemented() - {"constructor"})
    assert not orphaned, (
        f"index.d.ts declares these but index.js does not implement them: "
        f"{orphaned}"
    )
