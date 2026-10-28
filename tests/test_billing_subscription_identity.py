"""Stripe subscription events: access must follow the subscription that is actually current.

Independent expectations: a customer who upgraded by buying a second subscription keeps
access when the first is cancelled; a customer whose current subscription is cancelled
loses it, whatever order Stripe delivered the checkouts in.
"""
import pytest
from assurance.billing.accounts import AccountStore


@pytest.fixture
def store(tmp_path):
    return AccountStore(str(tmp_path / "accounts.db"))


def checkout(store, sub, event, session, created):
    return store.apply_checkout(
        event_id=event, session_id=session, email="buyer@example.invalid", company="Acme",
        tier="cell", stripe_customer_id="cus_1", stripe_subscription_id=sub,
        event_created=created)


def cancel(store, sub, created, event="evt_del"):
    return store.apply_subscription_event(
        event_id=event, kind="customer.subscription.deleted", stripe_customer_id="cus_1",
        status="cancelled", tier="free", event_created=created, hold_if_unknown=True,
        stripe_subscription_id=sub)


def acct(store):
    return store.account_by_customer("cus_1")


def test_cancelling_the_superseded_subscription_keeps_access(store):
    checkout(store, "sub_A", "e1", "cs1", 1000)
    checkout(store, "sub_B", "e2", "cs2", 2000)
    cancel(store, "sub_A", 3000)
    assert acct(store).status == "active" and acct(store).tier == "cell"


def test_cancelling_the_only_subscription_ends_access(store):
    checkout(store, "sub_A", "e1", "cs1", 1000)
    cancel(store, "sub_A", 3000)
    assert acct(store).status == "cancelled" and acct(store).tier == "free"


@pytest.mark.parametrize("order", [("A", "B"), ("B", "A")])
def test_checkout_delivery_order_does_not_decide_which_cancellation_counts(store, order):
    """Whichever checkout Stripe delivers first, the later-created subscription (B) is the
    current one; cancelling it must end access."""
    times = {"A": 1000, "B": 2000}
    for who in order:
        checkout(store, f"sub_{who}", f"e_{who}", f"cs_{who}", times[who])
    assert acct(store).stripe_subscription_id == "sub_B"
    assert cancel(store, "sub_B", 3000) == "applied"
    assert acct(store).status == "cancelled"


def test_a_replayed_cancellation_is_idempotent(store):
    checkout(store, "sub_A", "e1", "cs1", 1000)
    assert cancel(store, "sub_A", 3000, event="evt_x") == "applied"
    assert cancel(store, "sub_A", 3000, event="evt_x") == "duplicate"
    assert acct(store).status == "cancelled"
