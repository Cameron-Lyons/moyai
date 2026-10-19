"""Spend limit configuration, resolution and evaluation on SQLite and with --postgres-backend."""
import json
import threading
from dataclasses import dataclass
from decimal import Decimal

import pytest
from app import spend_limits
from app.db import Store
from app.spend_limits import (
    MAX_LIMIT_USD,
    STALE,
    InvalidSpendLimit,
    SpendLimitChanges,
    SpendLimitNotFound,
    SpendLimits,
    SpendLimitSet,
    StaleRevision,
    evaluate,
    limit_ids,
    limits_from_rows,
    parse_id,
)
from fastapi.exceptions import RequestValidationError


@dataclass(frozen=True)
class Actor:
    id: str
    email: str


ADMIN = Actor('google:1', 'Finance@Example.com')


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def limits(store):
    return SpendLimits(store)


def events(store):
    return sorted(({**row, 'details': json.loads(row['details'])} for row in store.rows(
        'SELECT action,actor,resource_type,resource_id,details FROM governance_audit_events')),
        key=lambda row: (row['resource_id'], row['action']))


def change(identity, limit_usd, revision=0):
    return {'id': identity, 'limit_usd': limit_usd, 'revision': revision}


def rows(listing):
    return {row['id']: (row['limit_usd'], row['revision']) for row in listing['limits']}


# Identifiers and validation


@pytest.mark.parametrize(('value', 'expected'), [
    ('organization', ('organization', 'organization', '')),
    ('user-default', ('user-default', 'user-default', '')),
    (' session-default ', ('session-default', 'session-default', '')),
    ('user:Bob@Example.COM', ('user:bob@example.com', 'user', 'bob@example.com')),
    ('user: bob@example.com ', ('user:bob@example.com', 'user', 'bob@example.com')),
])
def test_ids_are_normalized(value, expected):
    assert parse_id(value) == expected


@pytest.mark.parametrize('value', ['', 'org', 'Organization', 'user', 'user:', 'user:bob', 'User:bob@example.com',
                                   'user:bob@@example.com', 'user:' + 'a' * 250 + '@x.com', None, 7, 'user:b o@x.com'])
def test_unknown_ids_are_rejected(value):
    with pytest.raises(InvalidSpendLimit) as caught:
        parse_id(value)
    assert caught.value.status_code == 422


@pytest.mark.parametrize('amount', [None, 0, 0.01, 19.99, 5000, 1234.5, MAX_LIMIT_USD, 999_999.99])
def test_limits_accept_null_zero_and_two_decimal_amounts(amount):
    parsed = SpendLimitChanges.model_validate({'changes': [change('organization', amount)]}).changes[0]
    assert parsed.limit_usd == amount and (amount is None or isinstance(parsed.limit_usd, float))


@pytest.mark.parametrize('amount', [-0.01, -1, MAX_LIMIT_USD + 0.01, 1e9, 0.001, 0.1 + 0.2, 1e-7, float('nan'),
                                    float('inf'), True, '5', [5]])
def test_limits_reject_out_of_range_imprecise_and_non_numeric_amounts(amount):
    with pytest.raises(RequestValidationError) as caught:
        spend_limits.validated(SpendLimitChanges, {'changes': [change('organization', amount)]})
    assert all('input' not in error for error in caught.value.errors())
    assert f'{MAX_LIMIT_USD:,} USD' in spend_limits._RANGE


@pytest.mark.parametrize('payload', [
    {'changes': []}, {'changes': [change('organization', 1)] * 51}, {'changes': [{'id': 'organization', 'revision': 0}]},
    {'changes': [change('organization', 1, revision=-1)]}, {'changes': [change('organization', 1, revision=True)]},
    {'changes': [{**change('organization', 1), 'kind': 'user'}]}, {'changes': [change('teams', 1)]},
    {'changes': [change('organization', 1)], 'extra': True},
])
def test_change_sets_are_bounded_and_closed(payload):
    with pytest.raises(RequestValidationError):
        spend_limits.validated(SpendLimitChanges, payload)


# Service


def test_listing_always_has_singletons_then_overrides_by_email(limits):
    assert limits.listing() == {'limits': [
        {'id': identity, 'kind': identity, 'subject': '', 'limit_usd': None, 'revision': 0, 'updated_at': None,
         'updated_by': ''} for identity in ('organization', 'user-default', 'session-default')]}
    listing = limits.save([change('user:zed@example.com', 5), change('user:Amy@Example.com', None),
                           change('organization', 5000)], ADMIN)
    assert [row['id'] for row in listing['limits']] == [
        'organization', 'user-default', 'session-default', 'user:amy@example.com', 'user:zed@example.com']
    organization = listing['limits'][0]
    assert organization['limit_usd'] == 5000.0 and isinstance(organization['limit_usd'], float)
    assert (organization['revision'], organization['updated_by']) == (1, 'finance@example.com')
    assert organization['updated_at'].endswith('+00:00')
    assert listing['limits'][3] == {**listing['limits'][3], 'kind': 'user', 'subject': 'amy@example.com',
                                    'limit_usd': None, 'revision': 1}
    assert limits.listing() == listing


def test_saves_are_revisioned_and_audit_each_changed_row(store, limits):
    limits.save({'changes': [change('organization', 5000), change('user-default', 200)]}, ADMIN)
    listing = limits.save({'changes': [change('organization', 0, revision=1), change('user-default', 200, revision=1),
                                       change('user:bob@example.com', 12.5)]}, ADMIN)
    assert rows(listing) == {'organization': (0.0, 2), 'user-default': (200.0, 1), 'session-default': (None, 0),
                             'user:bob@example.com': (12.5, 1)}
    assert events(store) == [
        {'action': 'spend_limit.created', 'actor': 'finance@example.com', 'resource_type': 'spend_limit',
         'resource_id': 'organization',
         'details': {'kind': 'organization', 'limit_usd': 5000.0, 'previous_usd': None, 'revision': 1}},
        {'action': 'spend_limit.updated', 'actor': 'finance@example.com', 'resource_type': 'spend_limit',
         'resource_id': 'organization',
         'details': {'kind': 'organization', 'limit_usd': 0.0, 'previous_usd': 5000.0, 'revision': 2}},
        {'action': 'spend_limit.created', 'actor': 'finance@example.com', 'resource_type': 'spend_limit',
         'resource_id': 'user-default',
         'details': {'kind': 'user-default', 'limit_usd': 200.0, 'previous_usd': None, 'revision': 1}},
        {'action': 'spend_limit.created', 'actor': 'finance@example.com', 'resource_type': 'spend_limit',
         'resource_id': 'user:bob@example.com',
         'details': {'kind': 'user', 'limit_usd': 12.5, 'previous_usd': None, 'revision': 1}},
    ]


def test_unchanged_values_write_nothing(store, limits):
    limits.save([change('organization', None), change('session-default', None)], ADMIN)  # Never saved: already null.
    assert store.rows('SELECT * FROM spend_limits') == [] and events(store) == []
    limits.save([change('session-default', 20)], ADMIN)
    assert rows(limits.save([change('session-default', 20.0, revision=1)], ADMIN))['session-default'] == (20.0, 1)
    # A null person override is meaningful (no limit despite a default), so it is created.
    assert rows(limits.save([change('user:bob@example.com', None)], ADMIN))['user:bob@example.com'] == (None, 1)
    assert len(events(store)) == 2


def test_stale_revisions_reject_the_whole_change_set(store, limits):
    limits.save([change('organization', 100)], ADMIN)
    for stale in ([change('organization', 50)], [change('user-default', 10), change('organization', 50, revision=2)],
                  [change('user-default', 10, revision=1)]):
        with pytest.raises(StaleRevision) as caught:
            limits.save(stale, ADMIN)
        assert (caught.value.status_code, caught.value.detail) == (409, STALE)
    assert rows(limits.listing()) == {'organization': (100.0, 1), 'user-default': (None, 0),
                                      'session-default': (None, 0)}
    assert len(events(store)) == 1


def test_duplicate_ids_after_normalization_are_rejected(store, limits):
    with pytest.raises(InvalidSpendLimit) as caught:
        limits.save([change('user:bob@example.com', 1), change('user:BOB@example.com', 2)], ADMIN)
    assert (caught.value.status_code, caught.value.detail) == (422, 'Change each spend limit once.')
    assert store.rows('SELECT * FROM spend_limits') == []


def test_failed_audit_rolls_back_every_row(store, limits, monkeypatch):
    calls = []

    def fail_second(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise RuntimeError('audit unavailable')
        return record(*args, **kwargs)
    record = spend_limits.record_event_in
    monkeypatch.setattr(spend_limits, 'record_event_in', fail_second)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        limits.save([change('organization', 1), change('user-default', 2)], ADMIN)
    assert store.rows('SELECT * FROM spend_limits') == [] and events(store) == []


def test_override_capacity_is_bounded(store, limits, monkeypatch):
    monkeypatch.setattr(spend_limits, 'MAX_USER_LIMITS', 1)
    limits.save([change('user:a@example.com', 1)], ADMIN)
    with pytest.raises(spend_limits.SpendLimitCapacity):
        limits.save([change('user:b@example.com', 1)], ADMIN)
    limits.save([change('user:a@example.com', 2, revision=1), change('organization', 3)], ADMIN)  # Updates still work.
    assert len(events(store)) == 3


def test_delete_removes_only_person_overrides(store, limits):
    limits.save([change('user-default', 200), change('user:bob@example.com', 500)], ADMIN)
    with pytest.raises(InvalidSpendLimit) as singleton:
        limits.delete('user-default', 1, ADMIN)
    assert singleton.value.status_code == 422
    with pytest.raises(InvalidSpendLimit):
        limits.delete('user:not-an-email', 1, ADMIN)
    with pytest.raises(SpendLimitNotFound) as missing:
        limits.delete('user:amy@example.com', 0, ADMIN)
    assert missing.value.status_code == 404
    with pytest.raises(StaleRevision):
        limits.delete('user:bob@example.com', 2, ADMIN)
    with pytest.raises(TypeError):
        limits.delete('user:bob@example.com', '1', ADMIN)  # type: ignore[arg-type]
    assert limits.resolve('bob@example.com').user == 500.0
    assert limits.delete('user:Bob@Example.com', 1, ADMIN) == {'id': 'user:bob@example.com', 'deleted': True}
    assert limits.resolve('bob@example.com').user == 200.0
    deleted = events(store)[-1]
    assert deleted == {'action': 'spend_limit.deleted', 'actor': 'finance@example.com',
                       'resource_type': 'spend_limit', 'resource_id': 'user:bob@example.com',
                       'details': {'kind': 'user', 'limit_usd': None, 'previous_usd': 500.0, 'revision': 1}}
    assert len(events(store)) == 3


def test_resolve_uses_the_override_else_the_default(limits):
    assert limits.resolve('bob@example.com') == SpendLimitSet() and SpendLimitSet().unlimited
    limits.save([change('organization', 5000), change('user-default', 200), change('session-default', 20),
                 change('user:bob@example.com', 500), change('user:amy@example.com', None)], ADMIN)
    assert limits.resolve(' Bob@Example.com ') == SpendLimitSet(5000.0, 500.0, 20.0)
    assert limits.resolve('amy@example.com') == SpendLimitSet(5000.0, None, 20.0)  # Null override: no limit.
    for email in ('carol@example.com', '', None, 'not an email'):
        assert limits.resolve(email) == SpendLimitSet(5000.0, 200.0, 20.0)
    assert not limits.resolve('bob@example.com').unlimited


def test_actor_is_required_before_any_write(store, limits):
    for actor in (object(), Actor('', ''), 'finance@example.com'):
        with pytest.raises(TypeError):
            limits.save([change('organization', 1)], actor)
    assert limits.save([change('organization', 1)], Actor('slack:T1:U1', ''))['limits'][0]['updated_by'] == 'slack:T1:U1'
    assert len(events(store)) == 1


def test_concurrent_creates_serialize_on_the_writer_lock(store, limits):
    barrier, results = threading.Barrier(4), []

    def create(amount):
        barrier.wait()
        try:
            results.append(limits.save([change('organization', amount)], ADMIN))
        except StaleRevision as error:
            results.append(error)
    threads = [threading.Thread(target=create, args=(amount,)) for amount in (1, 2, 3, 4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, StaleRevision) for result in results) == 3
    assert len(events(store)) == 1 and rows(limits.listing())['organization'][1] == 1


def test_recreated_override_never_reuses_a_deleted_revision(store, limits):
    """Regression: a deleted override restarted at revision 1, so a stale editor overwrote its replacement."""
    limits.save([change('user:bob@example.com', 5)], ADMIN)
    limits.save([change('user:bob@example.com', 6, revision=1)], ADMIN)
    limits.delete('user:bob@example.com', 2, ADMIN)
    assert rows(limits.save([change('user:bob@example.com', 7)], ADMIN))['user:bob@example.com'] == (7.0, 3)
    for stale in (1, 2):  # Editors still showing the deleted override.
        with pytest.raises(StaleRevision):
            limits.save([change('user:bob@example.com', 1000, revision=stale)], ADMIN)
    limits.delete('user:bob@example.com', 3, ADMIN)
    assert rows(limits.save([change('user:bob@example.com', None)], ADMIN))['user:bob@example.com'] == (None, 4)
    assert rows(limits.save([change('user:amy@example.com', 1)], ADMIN))['user:amy@example.com'] == (1.0, 1)
    created = sorted(event['details']['revision'] for event in events(store) if event['action'] == 'spend_limit.created')
    assert created == [1, 1, 3, 4]


def test_writers_recheck_spend_manage_inside_the_transaction(store, tmp_path):
    from app.config import Settings
    from app.enterprise_roles import GovernanceActor, GovernanceForbidden, RoleAssignment, RoleCreate
    from app.user_roles import UserRoles
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    roles = UserRoles(store, settings)
    limits = SpendLimits(store, roles=roles.enterprise)
    owner = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin', kind='individual')
    finance = GovernanceActor(id='google:fin', email='Fin@Example.com', kind='individual')

    def spend_events():
        return [event for event in events(store) if event['resource_type'] == 'spend_limit']
    # The route's snapshot is never trusted alone: a member holds no spend.manage in the store.
    with pytest.raises(GovernanceForbidden):
        limits.save([change('organization', 1)], finance)
    roles.enterprise.create(RoleCreate(id='finance', name='Finance', permissions=['spend.manage', 'spend.read']), owner)
    roles.enterprise.assign(RoleAssignment(email='fin@example.com', role_id='finance', revision=0), owner)
    listing = limits.save([change('organization', 1), change('user:bob@example.com', 2)], finance)
    assert [(row['id'], row['updated_by']) for row in listing['limits'][:1]] == [('organization', 'fin@example.com')]
    settings.password_login_enabled, settings.workspace_password = True, 'test-only-shared-admin-password'
    shared = GovernanceActor(id='shared:password:admin', builtin_role='admin')
    assert limits.save([change('organization', 3, revision=1)], shared)['limits'][0]['updated_by'] == \
        'Shared password admin'
    # Revoked after the route checked it: the writer refuses and records nothing.
    roles.enterprise.assign(RoleAssignment(email='fin@example.com', role_id='member', revision=1), owner)
    before = spend_events()
    with pytest.raises(GovernanceForbidden):
        limits.delete('user:bob@example.com', 1, finance)
    with pytest.raises(GovernanceForbidden):
        limits.save([change('organization', 4, revision=2)], finance)
    assert spend_events() == before and limits.resolve('bob@example.com').user == 2.0


# Pure resolution and evaluation


def test_limit_ids_and_rows_resolution():
    assert limit_ids('Bob@Example.com') == ('organization', 'user-default', 'session-default', 'user:bob@example.com')
    assert limit_ids('') == limit_ids(None) == ('organization', 'user-default', 'session-default')
    stored = [{'id': 'organization', 'limit_usd': Decimal(10)}, {'id': 'user-default', 'limit_usd': 5},
              {'id': 'user:bob@example.com', 'limit_usd': None}, {'id': 'session-default', 'limit_usd': 2.5}]
    assert limits_from_rows(stored, 'BOB@example.com') == SpendLimitSet(10.0, None, 2.5)
    assert limits_from_rows(stored, 'amy@example.com') == SpendLimitSet(10.0, 5.0, 2.5)
    assert limits_from_rows([], 'bob@example.com').unlimited


@pytest.mark.parametrize('corrupt', [float('nan'), float('inf'), -1, 'abc', True, Decimal('NaN')])
def test_corrupt_stored_limits_block(corrupt):
    assert limits_from_rows([{'id': 'organization', 'limit_usd': corrupt}], '') == SpendLimitSet(organization=0.0)


@pytest.mark.parametrize(('limit_set', 'usage', 'expected'), [
    (SpendLimitSet(), {}, []),
    (SpendLimitSet(), {'organization': float('nan'), 'user': None}, []),  # Unlimited scopes ignore usage.
    (SpendLimitSet(organization=0), {'organization': 0}, ['organization']),  # Zero blocks immediately.
    (SpendLimitSet(user=0.0), {'user': Decimal(0)}, ['user']),
    (SpendLimitSet(organization=100), {'organization': 99.99}, []),
    (SpendLimitSet(organization=100), {'organization': 100}, ['organization']),  # Reached counts as exceeded.
    (SpendLimitSet(organization=100), {'organization': Decimal('100.000001')}, ['organization']),
    (SpendLimitSet(session=0.1), {'session': Decimal('0.1')}, ['session']),  # Exact, not binary-float, equality.
    (SpendLimitSet(session=0.1), {'session': Decimal('0.0999999999')}, []),
    (SpendLimitSet(session=0.3), {'session': 0.1 + 0.2}, ['session']),
    (SpendLimitSet(user=19.99), {'user': Decimal('19.99')}, ['user']),
    (SpendLimitSet(user=19.99), {'user': Decimal('19.98')}, []),
    (SpendLimitSet(5, 5, 5), {'organization': 9, 'user': 9, 'session': 9}, ['organization', 'user', 'session']),
    (SpendLimitSet(5, 5, 5), {'organization': 1, 'user': 9, 'session': 9}, ['user', 'session']),
    (SpendLimitSet(5, None, 5), {'organization': 1, 'session': 5}, ['session']),
    # A limited scope with unknown usage fails closed.
    (SpendLimitSet(user=5), {}, ['user']),
    (SpendLimitSet(user=5), {'user': None}, ['user']),
    (SpendLimitSet(user=5), {'user': float('nan')}, ['user']),
    (SpendLimitSet(user=5), {'user': float('inf')}, ['user']),
    (SpendLimitSet(user=5), {'user': -0.01}, ['user']),
    (SpendLimitSet(user=5), {'user': Decimal('NaN')}, ['user']),
    (SpendLimitSet(user=5), {'user': Decimal('sNaN')}, ['user']),
    (SpendLimitSet(user=5), {'user': Decimal('-Infinity')}, ['user']),
])
def test_evaluate_reports_reached_scopes_in_priority_order(limit_set, usage, expected):
    assert evaluate(limit_set, usage) == expected


@pytest.mark.parametrize(('limit_set', 'usage'), [
    (SpendLimitSet(user=5), {'user': '1'}), (SpendLimitSet(user=5), {'user': True}),
    ({'user': 5}, {'user': 1}), (SpendLimitSet(user=5), [('user', 1)]),
])
def test_evaluate_rejects_malformed_arguments(limit_set, usage):
    with pytest.raises(TypeError):
        evaluate(limit_set, usage)
