"""Spend limit configuration, resolution and evaluation on SQLite and with --postgres-backend."""
import json
import threading
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction

import pytest
from app import spend_limits
from app.db import Store
from app.spend_limits import (
    MAX_LIMIT_USD,
    REACHED,
    STALE,
    WARNING_RATIO,
    InvalidSpendLimit,
    SpendLimitChanges,
    SpendLimitNotFound,
    SpendLimitReached,
    SpendLimits,
    SpendLimitSet,
    StaleRevision,
    evaluate,
    evaluation,
    level,
    limit_ids,
    limits_from_rows,
    parse_id,
    refusal,
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
         'updated_by': ''} for identity in ('organization', 'user-default', 'session-default')],
        'group_limits': [], 'directory_groups': [], 'orphaned_group_limits': []}
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
    assert limits.resolve(' Bob@Example.com ') == SpendLimitSet(5000.0, 500.0, 20.0, 'override')
    assert limits.resolve('amy@example.com') == SpendLimitSet(5000.0, None, 20.0, 'override')  # Null: no limit.
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
    assert limits_from_rows(stored, 'BOB@example.com') == SpendLimitSet(10.0, None, 2.5, 'override')
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


# Directory group tiers

ENG, FIN, OPS, GONE = '0e' * 16, 'f1' * 16, '0a' * 16, 'de' * 16


def directory(store, groups=(), users=()):
    """groups: (id, name, deleted); users: (id, email, active, deleted, group ids)."""
    with store.connect() as conn:
        conn.begin_write()
        for identity, name, deleted in groups:
            conn.execute('''INSERT INTO scim_groups(id,display_name,display_key,deleted_at,created_at,updated_at,revision)
                VALUES(?,?,?,?,'now','now',1)''', (identity, name, name.casefold(), 'then' if deleted else ''))
        for identity, email, active, deleted, member_of in users:
            conn.execute('''INSERT INTO scim_users(id,user_name,profile,active,deleted_at,created_at,updated_at,revision)
                VALUES(?,?,'{}',?,?,'now','now',1)''', (identity, email, int(active), 'then' if deleted else ''))
            for group in member_of:
                conn.execute('INSERT INTO scim_group_members(group_id,user_id) VALUES(?,?)', (group, identity))


@pytest.fixture
def groups(store, limits):
    directory(store, groups=[(ENG, 'Engineering', False), (FIN, 'Finance', False), (OPS, 'Operations', False),
                             (GONE, 'Retired', True)], users=[
        ('u-bob', 'bob@example.com', True, False, [ENG, FIN, GONE]),
        ('u-amy', 'amy@example.com', True, False, [FIN]),
        # Not active, or a tombstone sharing an email: neither is a live membership.
        ('u-dan', 'dan@example.com', False, False, [ENG]),
        ('u-old', 'amy@example.com', True, True, [ENG, OPS]),
        ('u-eve', 'eve@example.com', True, False, [GONE]),
    ])


def tier(group, limit_usd, revision=0):
    return change('group:' + group, limit_usd, revision)


@pytest.mark.parametrize(('value', 'expected'), [
    ('group:' + ENG, ('group:' + ENG, 'group', ENG)),
    (' group:' + ENG.upper() + ' ', ('group:' + ENG, 'group', ENG)),
])
def test_group_ids_are_normalized(value, expected):
    assert parse_id(value) == expected


@pytest.mark.parametrize('value', ['group:', 'group', 'Group:' + ENG, 'group:' + ENG[:-1], 'group:' + ENG + '0',
                                   'group:' + 'g' * 32, 'group:bob@example.com', 'group:user:bob@example.com'])
def test_malformed_group_ids_are_rejected(value):
    with pytest.raises(InvalidSpendLimit) as caught:
        parse_id(value)
    assert caught.value.status_code == 422 and 'group:<directory group ID>' in caught.value.detail


def test_tiers_are_revisioned_and_audited_with_their_group(store, limits, groups):
    listing = limits.save([tier(ENG, 50), tier(FIN, None), change('user-default', 20)], ADMIN)
    assert listing['group_limits'] == [
        {'id': 'group:' + ENG, 'group_id': ENG, 'group_name': 'Engineering', 'member_count': 1, 'limit_usd': 50.0,
         'revision': 1, 'updated_at': listing['group_limits'][0]['updated_at'], 'updated_by': 'finance@example.com'},
        {'id': 'group:' + FIN, 'group_id': FIN, 'group_name': 'Finance', 'member_count': 2, 'limit_usd': None,
         'revision': 1, 'updated_at': listing['group_limits'][1]['updated_at'], 'updated_by': 'finance@example.com'},
    ]
    assert [group['display_name'] for group in listing['directory_groups']] == ['Engineering', 'Finance', 'Operations']
    assert [group['member_count'] for group in listing['directory_groups']] == [1, 2, 0]
    # Unchanged values write nothing; a change advances the revision.
    limits.save([tier(ENG, 50, revision=1), tier(FIN, None, revision=1)], ADMIN)
    assert limits.save([tier(ENG, 75.5, revision=1)], ADMIN)['group_limits'][0]['revision'] == 2
    assert limits.delete('group:' + ENG.upper(), 2, ADMIN) == {'id': 'group:' + ENG, 'deleted': True}
    tiers = [event for event in events(store) if event['resource_id'].startswith('group:')]
    assert [(event['action'], event['resource_id'], event['details']) for event in tiers] == [
        ('spend_limit.created', 'group:' + ENG,
         {'kind': 'group', 'group_name': 'Engineering', 'limit_usd': 50.0, 'previous_usd': None, 'revision': 1}),
        ('spend_limit.deleted', 'group:' + ENG,
         {'kind': 'group', 'group_name': 'Engineering', 'limit_usd': None, 'previous_usd': 75.5, 'revision': 2}),
        ('spend_limit.updated', 'group:' + ENG,
         {'kind': 'group', 'group_name': 'Engineering', 'limit_usd': 75.5, 'previous_usd': 50.0, 'revision': 2}),
        ('spend_limit.created', 'group:' + FIN,
         {'kind': 'group', 'group_name': 'Finance', 'limit_usd': None, 'previous_usd': None, 'revision': 1}),
    ]
    # A re-created tier continues after its deleted revision, so a stale editor cannot overwrite it.
    assert limits.save([tier(ENG, 10)], ADMIN)['group_limits'][0]['revision'] == 3
    for stale in (1, 2):
        with pytest.raises(StaleRevision):
            limits.save([tier(ENG, 1000, revision=stale)], ADMIN)


def test_tiers_need_a_live_directory_group(store, limits, groups):
    for group in (GONE, 'ab' * 16):
        with pytest.raises(SpendLimitNotFound) as caught:
            limits.save([change('organization', 5), tier(group, 5)], ADMIN)
        assert (caught.value.status_code, caught.value.detail) == (404, 'Directory group not found.')
    with pytest.raises(SpendLimitNotFound):
        limits.delete('group:' + ENG, 1, ADMIN)
    assert store.rows('SELECT * FROM spend_limits') == store.rows('SELECT * FROM spend_group_limits') == []
    assert events(store) == []


def test_mixed_batches_are_atomic_and_stale_tiers_reject_them(store, limits, groups):
    limits.save([tier(ENG, 50)], ADMIN)
    for stale in ([change('user:bob@example.com', 5), tier(ENG, 60)],
                  [tier(FIN, 5), tier(ENG, 60, revision=2)]):
        with pytest.raises(StaleRevision):
            limits.save(stale, ADMIN)
    assert rows(limits.listing()) == {'organization': (None, 0), 'user-default': (None, 0),
                                      'session-default': (None, 0)}
    assert [(row['group_id'], row['limit_usd']) for row in limits.listing()['group_limits']] == [(ENG, 50.0)]
    with pytest.raises(InvalidSpendLimit, match='once'):
        limits.save([tier(FIN, 1), tier(FIN.upper(), 2)], ADMIN)
    listing = limits.save([change('user:bob@example.com', 5), tier(FIN, 7), tier(ENG, 60, revision=1)], ADMIN)
    assert [(row['group_id'], row['limit_usd'], row['revision']) for row in listing['group_limits']] == [
        (ENG, 60.0, 2), (FIN, 7.0, 1)]
    assert len(events(store)) == 4


def test_tier_capacity_is_bounded(store, limits, groups, monkeypatch):
    monkeypatch.setattr(spend_limits, 'MAX_GROUP_LIMITS', 1)
    limits.save([tier(ENG, 1)], ADMIN)
    with pytest.raises(spend_limits.SpendLimitCapacity, match='directory group'):
        limits.save([tier(FIN, 1)], ADMIN)
    limits.save([tier(ENG, 2, revision=1), change('user:bob@example.com', 3)], ADMIN)  # Updates still work.


def test_listing_separates_tiers_of_deleted_groups_so_they_can_be_removed(store, limits, groups, monkeypatch):
    limits.save([tier(ENG, 5), tier(OPS, 6), tier(FIN, None)], ADMIN)
    with store.connect() as conn:
        conn.begin_write()
        conn.execute("UPDATE scim_groups SET deleted_at='later' WHERE id IN (?,?)", (OPS, FIN))
    listing = limits.listing()
    assert [row['group_id'] for row in listing['group_limits']] == [ENG]
    assert not {OPS, FIN} & {row['id'] for row in listing['directory_groups']}
    # By the group's last name, with the id and revision a delete takes.
    assert [{key: row[key] for key in ('id', 'group_name', 'limit_usd', 'revision')}
            for row in listing['orphaned_group_limits']] == [
        {'id': 'group:' + FIN, 'group_name': 'Finance', 'limit_usd': None, 'revision': 1},
        {'id': 'group:' + OPS, 'group_name': 'Operations', 'limit_usd': 6.0, 'revision': 1}]
    assert listing['orphaned_group_limits'][0]['updated_by'] == 'finance@example.com'
    # They still count toward capacity until removed.
    support = 'ab' * 16
    directory(store, groups=[(support, 'Support', False)])
    monkeypatch.setattr(spend_limits, 'MAX_GROUP_LIMITS', 3)
    with pytest.raises(spend_limits.SpendLimitCapacity):
        limits.save([tier(support, 1)], ADMIN)
    # An orphaned tier can still be removed; its event keeps the group's last name.
    limits.delete('group:' + OPS, 1, ADMIN)
    assert [row['group_id'] for row in limits.listing()['orphaned_group_limits']] == [FIN]
    deleted, = (event for event in events(store) if event['action'] == 'spend_limit.deleted')
    assert deleted['details']['group_name'] == 'Operations'
    limits.save([tier(support, 1)], ADMIN)


def test_resolution_prefers_the_override_then_the_most_permissive_live_tier(store, limits, groups):
    limits.save([change('user-default', 20), change('organization', 1000)], ADMIN)
    assert limits.resolve('bob@example.com') == SpendLimitSet(1000.0, 20.0)  # No tier yet.
    # A tier replaces the default, even when lower.
    limits.save([tier(ENG, 5)], ADMIN)
    assert limits.resolve('bob@example.com') == SpendLimitSet(1000.0, 5.0, None, 'group', ENG)
    # The most permissive of the person's tiers applies.
    limits.save([tier(FIN, 50)], ADMIN)
    assert limits.resolve('bob@example.com') == SpendLimitSet(1000.0, 50.0, None, 'group', FIN)
    assert limits.resolve('amy@example.com') == SpendLimitSet(1000.0, 50.0, None, 'group', FIN)
    # Inactive users, tombstones sharing an email, and deleted groups never apply a tier.
    limits.save([tier(OPS, 0)], ADMIN)
    with store.connect() as conn:
        conn.begin_write()
        conn.execute('INSERT INTO spend_group_limits VALUES(?,?,?,?,?)', (GONE, None, 1, 'owner', 'now'))
    assert limits.resolve('dan@example.com') == SpendLimitSet(1000.0, 20.0)
    assert limits.resolve('eve@example.com') == SpendLimitSet(1000.0, 20.0)
    assert limits.resolve('amy@example.com').user == 50.0
    # Unlimited beats any amount; an override beats every tier, even unlimited ones.
    limits.save([tier(ENG, None, revision=1)], ADMIN)
    assert limits.resolve('bob@example.com') == SpendLimitSet(1000.0, None, None, 'group', ENG)
    limits.save([change('user:bob@example.com', 3)], ADMIN)
    assert limits.resolve('bob@example.com') == SpendLimitSet(1000.0, 3.0, None, 'override')
    for email in ('', None, 'not an email', 'carol@example.com'):
        assert limits.resolve(email) == SpendLimitSet(1000.0, 20.0)
    with store.connect() as conn:
        conn.begin_read()
        assert SpendLimits.effective_in(conn, ' Amy@Example.com') == {
            'email': 'amy@example.com', 'limit_usd': 50.0, 'source': 'group', 'group_id': FIN, 'group_name': 'Finance'}
        assert SpendLimits.effective_in(conn, 'bob@example.com') == {
            'email': 'bob@example.com', 'limit_usd': 3.0, 'source': 'override', 'group_id': '', 'group_name': ''}
        assert SpendLimits.effective_in(conn, 'carol@example.com')['source'] == 'default'
        with pytest.raises(InvalidSpendLimit):
            SpendLimits.effective_in(conn, 'carol')


def tiers(*values):
    return [{'id': f'group:{index:032x}', 'limit_usd': value} for index, value in enumerate(values, 1)]


@pytest.mark.parametrize(('rows', 'email', 'expected'), [
    (tiers(5, 50, 0), 'bob@example.com', SpendLimitSet(user=50.0, user_source='group', user_group=f'{2:032x}')),
    (tiers(5, None, 50), 'bob@example.com', SpendLimitSet(user=None, user_source='group', user_group=f'{2:032x}')),
    # Ties go to the lowest group id.
    (tiers(7, 7), 'bob@example.com', SpendLimitSet(user=7.0, user_source='group', user_group=f'{1:032x}')),
    (tiers(None, None), 'bob@example.com', SpendLimitSet(user=None, user_source='group', user_group=f'{1:032x}')),
    (tiers(0), 'bob@example.com', SpendLimitSet(user=0.0, user_source='group', user_group=f'{1:032x}')),
    # A corrupt tier blocks even when another tier is higher or unlimited.
    (tiers(50, float('nan'), None), 'bob@example.com',
     SpendLimitSet(user=0.0, user_source='group', user_group=f'{2:032x}')),
    (tiers(50, -1), 'bob@example.com', SpendLimitSet(user=0.0, user_source='group', user_group=f'{2:032x}')),
    (tiers(50, 'abc'), 'bob@example.com', SpendLimitSet(user=0.0, user_source='group', user_group=f'{2:032x}')),
    # The override wins, even when NULL; the default applies without tiers or an email.
    ([*tiers(50), {'id': 'user:bob@example.com', 'limit_usd': None}, {'id': 'user-default', 'limit_usd': 1}],
     'bob@example.com', SpendLimitSet(user=None, user_source='override')),
    ([*tiers(50), {'id': 'user-default', 'limit_usd': 1}], '', SpendLimitSet(user=1.0)),
    ([{'id': 'user-default', 'limit_usd': 1}], 'bob@example.com', SpendLimitSet(user=1.0)),
])
def test_tier_precedence_from_rows(rows, email, expected):
    assert limits_from_rows(rows, email) == expected


def test_delegated_spend_managers_cannot_change_their_own_groups_tier(store, groups, tmp_path):
    from app.config import Settings
    from app.enterprise_roles import GovernanceActor, GovernanceForbidden, RoleAssignment, RoleCreate
    from app.user_roles import UserRoles
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    roles = UserRoles(store, settings)
    limits = SpendLimits(store, roles=roles.enterprise)
    owner = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin', kind='individual')
    bob = GovernanceActor(id='google:bob', email='bob@example.com', kind='individual')
    roles.enterprise.create(RoleCreate(id='finance', name='Finance', permissions=['spend.manage']), owner)
    roles.enterprise.assign(RoleAssignment(email='bob@example.com', role_id='finance', revision=0), owner)
    limits.save([tier(ENG, 5)], owner)
    for attempt in (lambda: limits.save([tier(FIN, 500)], bob), lambda: limits.save([tier(ENG, 500, revision=1)], bob),
                    lambda: limits.delete('group:' + ENG, 1, bob)):
        with pytest.raises(GovernanceForbidden, match='group you belong to'):
            attempt()
    # Other groups, and their own override (unchanged behavior), remain theirs to manage.
    assert limits.save([tier(OPS, 5), change('user:bob@example.com', 9)], bob)['group_limits'][-1]['group_id'] == OPS
    # Built-in administrators may change any tier.
    limits.save([tier(ENG, 7, revision=1)], owner)


# Refusals and notices


@pytest.mark.parametrize(('limit_set', 'usage', 'exceeded', 'pending', 'reason'), [
    (SpendLimitSet(5, 5, 5), {'organization': 1, 'user': 1, 'session': 1}, [], [], None),
    (SpendLimitSet(5, 5, 5), {'organization': 9, 'user': 9, 'session': 9}, ['organization', 'user', 'session'], [],
     'organization'),
    (SpendLimitSet(None, 5, 5), {'user': 1, 'session': 5}, ['session'], [], 'session'),
    (SpendLimitSet(user=5), {'user': None}, ['user'], ['user'], 'pending'),
    # Recorded spend that reaches a limit wins over a scope awaiting a cost; waiting would not help.
    (SpendLimitSet(5, 5), {'organization': None, 'user': 5}, ['organization', 'user'], ['organization'], 'user'),
    # A zero limit refuses whatever the usage, so it is never pending.
    (SpendLimitSet(user=0), {'user': None}, ['user'], [], 'user'),
])
def test_refusal_reasons(limit_set, usage, exceeded, pending, reason):
    assert evaluation(limit_set, usage) == (exceeded, pending)
    assert refusal(limit_set, usage) == reason


def test_refusal_messages_are_fixed_and_carry_no_amounts():
    assert set(REACHED) == {'organization', 'user', 'session', 'pending'}
    for reason, message in REACHED.items():
        error = SpendLimitReached(reason)
        assert (error.status_code, error.detail, error.reason) == (403, message, reason)
        assert 'spend limit' in message and '$' not in message and not any(c.isdigit() for c in message)
    with pytest.raises(ValueError):
        SpendLimitReached('group')


@pytest.mark.parametrize(('limit', 'used', 'expected'), [
    (None, 10**6, 'ok'), (None, None, 'ok'),
    (0, None, 'reached'), (0, 0, 'reached'),
    (30, None, 'pending'),
    (30, 0, 'ok'), (30, Decimal('19.99'), 'ok'), (30, Decimal('20'), 'warning'), (30, 29.99, 'warning'),
    (30, 30, 'reached'), (30, 31, 'reached'),
    (0.03, Decimal('0.02'), 'warning'), (0.03, Decimal('0.019999'), 'ok'),
    (30, float('nan'), 'reached'), (30, -1, 'reached'),
])
def test_levels_warn_at_two_thirds(limit, used, expected):
    assert WARNING_RATIO == Fraction(2, 3)
    assert level(limit, used) == expected
