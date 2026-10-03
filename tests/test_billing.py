"""The Stripe webhook: what it accepts, what it refuses, what it writes.

Nothing here talks to Stripe. A webhook signature is an HMAC-SHA256 over
`<timestamp>.<payload>` with the endpoint's secret, so a payload can be signed
in the test and the handler's real verification path is exercised — not mocked
past. That matters more here than anywhere else in the suite: this is the
endpoint that decides who is on a paid tier, and until now no test touched it.

The three questions worth answering:

  * unconfigured — does it refuse, or does it process anyway?
  * mis-signed — does it refuse, or does it trust the body?
  * well-signed — does it write what it claims to write?

The first two are the free-money questions. The third is the one that was
silently broken: the renewal branch read a field the pinned Stripe API had
moved, so a successful renewal confirmed nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_db import get_db  # noqa: E402

SECRET = "whsec_test_secret"


def _sign(payload: str, secret: str = SECRET, ts: int | None = None) -> str:
    """A header Stripe would accept, computed here rather than fetched."""
    ts = ts or int(time.time())
    digest = hmac.new(
        secret.encode(), f"{ts}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    return f"t={ts},v1={digest}"


def _deliver(client, event: dict, *, secret: str = SECRET, signature: str | None = None):
    # Real events carry these; the SDK reads `event.object` during
    # verification, so a payload without it is not a realistic one.
    event.setdefault("object", "event")
    event.setdefault("id", "evt_test")
    payload = json.dumps(event)
    headers = {"Content-Type": "application/json"}
    headers["Stripe-Signature"] = signature if signature is not None else _sign(payload, secret)
    return client.post("/v1/billing/webhook", data=payload, headers=headers)


def _configured(monkeypatch):
    monkeypatch.setattr(api, "STRIPE_SECRET_KEY", "sk_test_not_a_real_key", raising=False)
    monkeypatch.setattr(api, "STRIPE_WEBHOOK_SECRET", SECRET, raising=False)


# ── The free-money questions ─────────────────────────────────────────────

def test_an_unconfigured_deployment_refuses_rather_than_processing(
    haldir_client, monkeypatch
) -> None:
    """The secret is what makes the body trustworthy. Without it the handler
    must not touch the database, whatever the request says — a 503 is Stripe's
    problem to retry, and an unsigned upgrade is a customer's problem forever."""
    monkeypatch.setattr(api, "STRIPE_SECRET_KEY", "", raising=False)
    monkeypatch.setattr(api, "STRIPE_WEBHOOK_SECRET", "", raising=False)

    r = _deliver(haldir_client, {
        "type": "checkout.session.completed",
        "data": {"object": {"customer": "cus_x", "metadata": {"tier": "usage"}}},
    })
    assert r.status_code == 503


def test_a_body_with_no_signature_is_refused(haldir_client, monkeypatch) -> None:
    _configured(monkeypatch)
    r = _deliver(haldir_client, {"type": "checkout.session.completed",
                                 "data": {"object": {}}}, signature="")
    assert r.status_code == 400


def test_a_signature_from_the_wrong_secret_is_refused(haldir_client, monkeypatch) -> None:
    """The interesting forgery: a well-formed signature that is simply not ours."""
    _configured(monkeypatch)
    r = _deliver(
        haldir_client,
        {"type": "checkout.session.completed",
         "data": {"object": {"customer": "cus_forged", "metadata": {"tier": "usage"}}}},
        secret="whsec_somebody_elses",
    )
    assert r.status_code == 400

    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT * FROM subscriptions WHERE stripe_customer_id = 'cus_forged'"
        ).fetchone()
    finally:
        conn.close()
    assert row is None, "a forged signature wrote a subscription"


def test_a_body_edited_after_signing_is_refused(haldir_client, monkeypatch) -> None:
    """Signed for one tenant, delivered as another."""
    _configured(monkeypatch)
    signed = json.dumps({"type": "checkout.session.completed",
                         "data": {"object": {"customer": "cus_a",
                                             "metadata": {"tenant_id": "tenant-a"}}}})
    tampered = signed.replace("tenant-a", "tenant-b")
    r = haldir_client.post(
        "/v1/billing/webhook", data=tampered,
        headers={"Content-Type": "application/json",
                 "Stripe-Signature": _sign(signed)},
    )
    assert r.status_code == 400


# ── And what a real one does ─────────────────────────────────────────────

def test_a_signed_checkout_activates_the_tier(haldir_client, monkeypatch) -> None:
    _configured(monkeypatch)
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "customer": "cus_real",
            "subscription": "sub_real",
            "metadata": {"tier": "usage", "tenant_id": "tenant-real"},
        }},
    }
    assert _deliver(haldir_client, event).status_code == 200

    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT tier, status FROM subscriptions WHERE stripe_subscription_id = 'sub_real'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "the checkout event wrote nothing"
    assert row["tier"] == "usage"
    assert row["status"] == "active"


def test_a_renewal_is_confirmed_from_either_spelling_of_the_field(
    haldir_client, monkeypatch
) -> None:
    """The bug this file was written for.

    `Invoice.subscription` was removed in the Stripe API this repo pins
    (2026-03-25.dahlia) and now lives under `parent.subscription_details`. The
    handler read only the old path, so a renewal that Stripe delivered
    successfully returned 200 and confirmed nothing — the subscription stayed
    whatever it was. Both spellings are exercised so neither can regress.
    """
    _configured(monkeypatch)
    _deliver(haldir_client, {
        "type": "checkout.session.completed",
        "data": {"object": {"customer": "cus_r", "subscription": "sub_renew",
                            "metadata": {"tier": "usage", "tenant_id": "t-renew"}}},
    })

    conn = get_db(api.DB_PATH)
    try:
        conn.execute(
            "UPDATE subscriptions SET status = 'past_due' WHERE stripe_subscription_id = 'sub_renew'"
        )
        conn.commit()
    finally:
        conn.close()

    # The shape the pinned API actually sends.
    modern = {
        "type": "invoice.payment_succeeded",
        "data": {"object": {
            "parent": {"subscription_details": {"subscription": "sub_renew"}},
            "lines": {"data": [{"period": {"end": 1900000000}}]},
        }},
    }
    assert _deliver(haldir_client, modern).status_code == 200

    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT status, current_period_end FROM subscriptions "
            "WHERE stripe_subscription_id = 'sub_renew'"
        ).fetchone()
    finally:
        conn.close()
    assert row["status"] == "active", (
        "the renewal was not confirmed — the subscription id was not found on the invoice"
    )
    assert row["current_period_end"] == 1900000000


def test_a_failed_payment_drops_the_tenant_to_free(haldir_client, monkeypatch) -> None:
    """No dunning, and no second write to remember.

    `_get_tenant_tier` honours a tier only while the status is 'active', so
    marking the row past_due is the whole downgrade — and a later successful
    payment restores it through the same resolution.
    """
    _configured(monkeypatch)
    _deliver(haldir_client, {
        "type": "checkout.session.completed",
        "data": {"object": {"customer": "cus_f", "subscription": "sub_fail",
                            "metadata": {"tier": "usage", "tenant_id": "t-fail"}}},
    })

    failed = {
        "type": "invoice.payment_failed",
        "data": {"object": {"parent": {"subscription_details": {"subscription": "sub_fail"}}}},
    }
    assert _deliver(haldir_client, failed).status_code == 200

    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT status FROM subscriptions WHERE stripe_subscription_id = 'sub_fail'"
        ).fetchone()
    finally:
        conn.close()
    assert row["status"] == "past_due"


def test_an_invoice_with_no_subscription_is_acknowledged_not_guessed(
    haldir_client, monkeypatch
) -> None:
    """Some invoices have nothing to do with a subscription. Saying so beats
    matching on whatever id happens to be empty."""
    _configured(monkeypatch)
    r = _deliver(haldir_client, {
        "type": "invoice.payment_succeeded",
        "data": {"object": {"lines": {"data": []}}},
    })
    assert r.status_code == 200
    assert r.get_json().get("note")


# ── Which tiers are for sale ─────────────────────────────────────────────

def test_enterprise_is_not_self_serve(haldir_client, bootstrap_key, monkeypatch) -> None:
    """Any authenticated key could ask for it before this.

    With a price configured, that handed out a checkout session for whatever
    the operator had set — including a negotiated price nobody had agreed to.
    """
    _configured(monkeypatch)
    r = haldir_client.post(
        "/v1/billing/checkout",
        json={"tier": "enterprise"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["code"] == "tier_not_purchasable"
