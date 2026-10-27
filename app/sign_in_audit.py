"""Sign-in, refusal and sign-out events in the governance audit (resource type sign_in).

Every organization sign-in method records the same actions, beside the OpenID
Connect enrollment events (identity_binding.created): sign_in.succeeded
{method, enrolled}, sign_in.refused {method, reason} and sign_in.signed_out
{method}. The resource is the OpenID Connect provider id, or the method itself
('google', 'cloudflare', 'password'). The actor is the verified email, the
shared password account's label, or 'anonymous' before anyone is verified.
Reasons are fixed values; codes, tokens, claims and passwords are never stored.

A successful sign-in records its event in the transaction that refreshes or
enrolls the account, so no session is issued without it. Otherwise an event
takes a write lock scoped to itself, so sign-in events never wait for each
other or pause native admissions. A refusal or sign-out caller may treat a
failed write as non-fatal; a sign-in issues no session without its event.

Every event a client can repeat without a new verified sign-in is keyed, so a
repeat inserts nothing: an Access sign-in or refusal per subject and minute, an
anonymous refusal per client network, reason and minute (anonymous_key), and a
sign-out once per session.
"""
from contextlib import contextmanager
from uuid import uuid4

from .governance_audit import event_id, record_event_in

METHODS = frozenset({'google', 'cloudflare', 'password', 'oidc'})


@contextmanager
def _writer(store, action, key):
    # Only a repeat of the same keyed event waits for this one.
    with store.connect(write_scope='sign-in:' + (uuid4().hex if key is None else event_id(action, key))) as conn:
        conn.begin_write()
        yield conn


def succeeded_in(conn, method, actor, *, enrolled, resource_id=None, key=None):
    """sign_in.succeeded in the caller's write transaction."""
    return record_event_in(conn, 'sign_in.succeeded', actor, 'sign_in', resource_id or method,
                           {'method': method, 'enrolled': enrolled}, key=key)


def succeeded(store, method, actor, *, enrolled, key):
    """sign_in.succeeded in its own transaction, once per key (an Access sign-in per minute)."""
    with _writer(store, 'sign_in.succeeded', key) as conn:
        return succeeded_in(conn, method, actor, enrolled=enrolled, key=key)


def anonymous_key(method, client, reason, resource_id=''):
    """One anonymous refusal per method (and provider), client network, reason and UTC minute.

    A refusal before anyone is verified is bounded only by its start throttle,
    which is per client and per process, so many clients could otherwise each
    add a permanent row per attempt.
    """
    from .governance_activity import minute_bucket
    return f'{method}\x1f{resource_id}\x1f{client}\x1f{reason}\x1f{minute_bucket()}'


def record(store, action, actor, method, *, resource_id=None, key=None, **details):
    """sign_in.refused or sign_in.signed_out in its own transaction."""
    if action not in {'sign_in.refused', 'sign_in.signed_out'} or method not in METHODS:
        raise ValueError('Record a sign-in refusal or sign-out for a known method.')
    with _writer(store, action, key) as conn:
        return record_event_in(conn, action, actor, 'sign_in', resource_id or method,
                               {'method': method, **details}, key=key)
