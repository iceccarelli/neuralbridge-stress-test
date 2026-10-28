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
def test_access_ends_only_when_no_live_subscription_remains(store, order):
    """Whichever checkout Stripe delivers first, the later-bought subscription (B) is the
    one the account follows. A customer who still pays for A (never cancelled) must keep
    access when B is cancelled; access ends when the last live subscription ends.

    (An earlier version of this test assumed buying B superseded A and expected access to
    end on B's cancellation. A was never cancelled, so that locked out a paying customer: the
    expectation was wrong, not the delivery order. Product main still behaves that way;
    neuralbridge#62 fixes it, so this test FAILS on main without #62.)
    """
    times = {"A": 1000, "B": 2000}
    for who in order:
        checkout(store, f"sub_{who}", f"e_{who}", f"cs_{who}", times[who])
    assert acct(store).stripe_subscription_id == "sub_B"
    assert cancel(store, "sub_B", 3000, event="evt_del_B") == "applied"
    assert acct(store).status == "active" and acct(store).tier == "cell"   # A still pays
    cancel(store, "sub_A", 4000, event="evt_del_A")
    assert acct(store).status == "cancelled" and acct(store).tier == "free"


def test_a_replayed_cancellation_is_idempotent(store):
    checkout(store, "sub_A", "e1", "cs1", 1000)
    assert cancel(store, "sub_A", 3000, event="evt_x") == "applied"
    assert cancel(store, "sub_A", 3000, event="evt_x") == "duplicate"
    assert acct(store).status == "cancelled"
