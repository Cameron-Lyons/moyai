"""Governance storage (revisions 23 to 25) and audit-event contract on SQLite or --postgres-backend."""
import json
import os
import re
import sqlite3

import pytest
from app import permissions
from app.database import INTEGRITY_ERRORS
from app.db import Store
from app.governance_audit import MAX_DETAILS_BYTES, record_event_in
from app.online_migrations import _versions
from app.schema_migrations import COMPONENTS, SCHEMA_COMPATIBILITY_REVISION, initialize_components

GOVERNANCE = ('enterprise_roles', 'scim', 'service_accounts', 'security_profiles', 'spend_limits',
              'governance_audit', 'governance_activity')
# Revision 25's additions, in creation order; revision 24 has none of them.
REVISION_25 = ('service_accounts', 'service_account_keys', 'spend_group_limits', 'governance_activity_events')
STAMP = '2026-10-26T00:00:00.000000+00:00'


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path)
    initialize_components(store)
    try:
        yield store
    finally:
        store.close()


def event(conn, **change):
    values = {'action': 'role.updated', 'actor': 'owner@example.com', 'resource_type': 'CustomRole',
              'resource_id': 'a' * 32, 'details': None, **change}
    return record_event_in(conn, values.pop('action'), values.pop('actor'), values.pop('resource_type'),
                           values.pop('resource_id'), values.pop('details'))


def test_governance_components_are_appended_and_idempotent(store):
    assert COMPONENTS[-len(GOVERNANCE):] == GOVERNANCE
    initialize_components(store)
    assert {'enterprise_roles', 'enterprise_role_assignments', 'enterprise_group_roles', 'scim_tokens',
            'scim_users', 'scim_groups', 'scim_group_members', 'security_profiles', 'security_profile_revisions',
            'security_profile_defaults', 'spend_limits', 'governance_audit_events', *REVISION_25} <= store.table_names()


def test_governance_module_initializers_need_only_the_core_store(tmp_path):
    from app import enterprise_roles, governance_audit, scim, security_profiles, spend_limits
    from app.schema_initializers import initialize_governance_activity, initialize_service_accounts
    store = Store(tmp_path / 'core-only')
    try:
        # Service constructors may initialize before other components in auto mode.
        for module in (governance_audit, spend_limits, security_profiles, scim, enterprise_roles):
            module.initialize_schema(store)
        initialize_service_accounts(store)
        initialize_governance_activity(store)
        assert {'governance_audit_events', *REVISION_25} <= store.table_names()
    finally:
        store.close()


def test_revision_25_is_appended_as_a_maintenance_revision():
    """Earlier digests are never rewritten, and revision-24 binaries cannot overlap revision 25.

    A revision-24 binary would ignore spend tiers and give a restrictive tier's
    members the default limit, so the compatibility floor advances with it.
    """
    versions = _versions()
    assert versions['23'] == '9447c4af35e4ff67061853a7ca863649981332b9936a80645439fd4edf85625c'
    assert versions['24'] == '23405097eea19ab2cac34e6484d7e9a32a9ca0b2a48cc9af6d45b53cfa2d8b1d'
    assert '25' in versions and SCHEMA_COMPATIBILITY_REVISION >= 25


def indexes(store, table):
    """{name: definition without whitespace} for the table's named indexes."""
    if store.database:
        rows = store.rows("""SELECT indexname AS name,indexdef AS sql FROM pg_indexes
            WHERE schemaname=current_schema() AND tablename=? AND indexname LIKE 'idx%'""", (table,))
    else:
        rows = store.rows("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                          (table,))
    return {row['name']: ''.join(row['sql'].split()) for row in rows}


def triggers(store, table):
    if store.database:
        return {row['tgname'] for row in store.rows(
            'SELECT tgname FROM pg_trigger WHERE tgrelid=CAST(? AS regclass) AND NOT tgisinternal', (table,))}
    return {row['name'] for row in store.rows(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,))}


def test_revision_25_indexes_and_triggers(store):
    initialize_components(store)  # Rerunning the migration keeps one copy of each object.
    collate = 'COLLATE"C"' if store.database else ''
    feed = f'created_at{collate},id{collate}'
    activity_indexes = indexes(store, 'governance_activity_events')
    assert {name: re.search(r'\(([^()]*)\)(?:WHERE|$)', sql).group(1) for name, sql in activity_indexes.items()} == {
        'idx_activity_audit_time': feed, 'idx_activity_audit_action': 'action,' + feed,
        'idx_activity_audit_actor': 'actor_key,' + feed, 'idx_activity_audit_resource': 'resource_type,' + feed,
        'idx_activity_audit_session': 'session_id,' + feed}
    assert [name for name, sql in activity_indexes.items() if 'WHERE' in sql] == ['idx_activity_audit_session']
    assert "session_id<>''" in activity_indexes['idx_activity_audit_session']
    assert not any('UNIQUE' in sql for sql in activity_indexes.values())
    accounts, keys = indexes(store, 'service_accounts'), indexes(store, 'service_account_keys')
    assert set(accounts) == {'idx_service_accounts_name'} and 'UNIQUE' in accounts['idx_service_accounts_name']
    assert '(name_key)' in accounts['idx_service_accounts_name']
    assert set(keys) == {'idx_service_account_keys_hash', 'idx_service_account_keys_account'}
    assert 'UNIQUE' in keys['idx_service_account_keys_hash'] and '(token_hash)' in keys['idx_service_account_keys_hash']
    assert 'UNIQUE' not in keys['idx_service_account_keys_account']
    assert '(account_id,created_at)' in keys['idx_service_account_keys_account']
    assert indexes(store, 'spend_group_limits') == {}
    assert triggers(store, 'governance_activity_events') == {'governance_activity_immutable'}
    assert not triggers(store, 'governance_audit_events') | triggers(store, 'spend_group_limits')
    if store.database:
        assert store.rows("""SELECT proname FROM pg_proc WHERE pronamespace=CAST(current_schema() AS regnamespace)
            AND proname='governance_activity_immutable'""") == [{'proname': 'governance_activity_immutable'}]


def activity(**change):
    values = {'id': 'a' * 32, 'action': 'sign_in.succeeded', 'outcome': 'success', 'actor': 'Person',
              'actor_key': 'person@example.com', 'resource_type': 'sign_in', 'resource_id': 'person@example.com',
              'created_at': STAMP, **change}
    return (f'INSERT INTO governance_activity_events({",".join(values)}) VALUES({",".join("?" * len(values))})',
            tuple(values.values()))


def assert_update_refused(store, statement):
    """Both backends refuse with an integrity error, as the privacy trigger does."""
    with pytest.raises(INTEGRITY_ERRORS) as refused:
        store.execute(statement)
    if not store.database:
        assert isinstance(refused.value, sqlite3.IntegrityError)
        assert 'Activity audit events are immutable' in str(refused.value)
        return
    # The adapter hides PostgreSQL's message; read the trigger's own error directly.
    import psycopg
    with psycopg.connect(os.environ['MOYAI_TEST_POSTGRES_URL']) as conn:
        conn.execute(f'SET search_path TO "{store.database.schema}"')
        with pytest.raises(psycopg.errors.CheckViolation, match='Activity audit events are immutable'):
            conn.execute(statement)


def test_activity_rows_are_immutable_but_can_be_purged(store):
    store.execute(*activity())
    store.execute(*activity(id='b' * 32, action='session.created', resource_type='session', session_id='c' * 32,
                            details='{"origin":"web"}'))
    saved = store.rows('SELECT * FROM governance_activity_events ORDER BY id')
    assert saved[0] == {
        'id': 'a' * 32, 'action': 'sign_in.succeeded', 'outcome': 'success', 'actor': 'Person',
        'actor_key': 'person@example.com', 'actor_id': '', 'resource_type': 'sign_in',
        'resource_id': 'person@example.com', 'session_id': '', 'client': '', 'details': '{}', 'created_at': STAMP}
    upsert = f"""INSERT INTO governance_activity_events(id,action,outcome,actor,actor_key,resource_type,resource_id,
        created_at) VALUES('{'a' * 32}','sign_in.succeeded','failed','Person','person','sign_in','person','{STAMP}')
        ON CONFLICT(id) DO UPDATE SET outcome=excluded.outcome"""
    for statement in ("UPDATE governance_activity_events SET outcome='denied'",
                      "UPDATE governance_activity_events SET details='{}' WHERE session_id<>''",
                      'UPDATE governance_activity_events SET id=id', upsert):
        assert_update_refused(store, statement)
    # Deterministic ids collapse retried writes without firing the trigger.
    statement, params = activity(outcome='failed')
    assert store.execute(statement + ' ON CONFLICT(id) DO NOTHING', params) == 0
    assert store.rows('SELECT * FROM governance_activity_events ORDER BY id') == saved
    with pytest.raises(INTEGRITY_ERRORS):
        store.execute(*activity())
    # An opt-in retention purge can still delete rows.
    assert store.execute('DELETE FROM governance_activity_events WHERE created_at<=?', (STAMP,)) == 2
    assert store.rows('SELECT * FROM governance_activity_events') == []


@pytest.mark.parametrize('change', [
    {'outcome': 'succeeded'}, {'outcome': ''}, {'outcome': None}, {'details': 'x' * 4097}, {'details': None},
    {'session_id': None}, {'actor_key': None},
])
def test_activity_rows_are_checked(store, change):
    with pytest.raises(INTEGRITY_ERRORS):
        store.execute(*activity(**change))
    store.execute(*activity(details='x' * 4096))
    assert store.rows('SELECT length(details) AS size FROM governance_activity_events') == [{'size': 4096}]


def test_spend_group_limits_bound_each_tier(store):
    insert = 'INSERT INTO spend_group_limits VALUES(?,?,?,?,?)'
    for group, limit in (('unlimited', None), ('blocked', 0), ('ceiling', 1_000_000), ('cents', 12.34)):
        store.execute(insert, (group, limit, 1, 'owner@example.com', STAMP))
    for limit, revision in ((-0.01, 1), (1_000_000.01, 1), (5, 0), (5, None)):
        with pytest.raises(INTEGRITY_ERRORS):
            store.execute(insert, ('rejected', limit, revision, 'owner@example.com', STAMP))
    with pytest.raises(INTEGRITY_ERRORS):  # One tier per group.
        store.execute(insert, ('cents', 5, 2, 'owner@example.com', STAMP))
    assert store.rows('SELECT group_id,limit_usd FROM spend_group_limits ORDER BY group_id') == [
        {'group_id': 'blocked', 'limit_usd': 0}, {'group_id': 'ceiling', 'limit_usd': 1_000_000},
        {'group_id': 'cents', 'limit_usd': 12.34}, {'group_id': 'unlimited', 'limit_usd': None}]
    for limit in (float('inf'), float('-inf')):
        with pytest.raises(INTEGRITY_ERRORS):
            store.execute(insert, ('infinite', limit, 1, 'owner@example.com', STAMP))
    if store.database:
        with pytest.raises(INTEGRITY_ERRORS):
            store.execute(insert, ('nan', float('nan'), 1, 'owner@example.com', STAMP))
        assert not store.rows("SELECT 1 FROM spend_group_limits WHERE group_id='nan'")
    else:
        # SQLite stores NaN as NULL (unlimited), so writers must reject non-finite limits themselves.
        store.execute(insert, ('nan', float('nan'), 1, 'owner@example.com', STAMP))
        assert store.rows("SELECT limit_usd FROM spend_group_limits WHERE group_id='nan'") == [{'limit_usd': None}]


def test_service_account_names_and_key_hashes_are_unique(store):
    account = 'INSERT INTO service_accounts VALUES(?,?,?,?,?,1,1,1,?,?,?,?)'
    key = "INSERT INTO service_account_keys VALUES(?,?,'SIEM',?,'moyai_sk_0123abcd','owner',?,?,'','','','')"
    expires = '2027-01-24T00:00:00.000000+00:00'
    store.execute(account, ('a' * 32, 'SIEM', 'siem', '', '["audit.read"]', 'owner', STAMP, 'owner', STAMP))
    with pytest.raises(INTEGRITY_ERRORS):  # Writers casefold name_key.
        store.execute(account, ('b' * 32, 'siem', 'siem', '', '[]', 'owner', STAMP, 'owner', STAMP))
    store.execute(key, ('c' * 32, 'a' * 32, 'f' * 64, STAMP, expires))
    with pytest.raises(INTEGRITY_ERRORS):
        store.execute(key, ('d' * 32, 'a' * 32, 'f' * 64, STAMP, expires))
    with pytest.raises(INTEGRITY_ERRORS):  # Expiry, last use and revocation have no defaults.
        store.execute("""INSERT INTO service_account_keys(id,account_id,label,token_hash,prefix,created_by,created_at)
            VALUES('e','a','SIEM','e','moyai_sk_','owner',?)""", (STAMP,))
    assert store.rows('SELECT account_id,expires_at,last_used_at,revoked_at FROM service_account_keys') == [
        {'account_id': 'a' * 32, 'expires_at': expires, 'last_used_at': '', 'revoked_at': ''}]


def test_revision_24_rows_survive_the_revision_25_upgrade(store):
    store.execute("INSERT INTO spend_limits VALUES('user-default','user-default','',25,3,'owner@example.com',?)",
                  (STAMP,))
    store.execute("INSERT INTO spend_limits VALUES('user:a@example.com','user','a@example.com',NULL,1,'owner',?)",
                  (STAMP,))
    store.execute("INSERT INTO scim_groups VALUES('group','entra-group','Engineering','engineering','',?,?,2)",
                  (STAMP, STAMP))
    store.execute("INSERT INTO enterprise_group_roles VALUES('group','reader',1,'owner',?)", (STAMP,))
    with store.connect() as conn:
        conn.begin_write()
        event(conn, action='spend_limit.updated', resource_type='spend_limit', resource_id='user-default')
    preserved = ('spend_limits', 'scim_groups', 'enterprise_group_roles', 'governance_audit_events')
    saved = {table: store.rows(f'SELECT * FROM {table} ORDER BY 1') for table in preserved}
    with store.connect() as conn:  # Reproduce revision 24's schema.
        for table in REVISION_25:
            conn.execute(f'DROP TABLE {table}')
        if store.database:
            conn.execute('DROP FUNCTION governance_activity_immutable()')
    assert not set(REVISION_25) & store.table_names()
    initialize_components(store)
    assert {table: store.rows(f'SELECT * FROM {table} ORDER BY 1') for table in preserved} == saved
    assert all(store.rows(f'SELECT * FROM {table}') == [] for table in REVISION_25)
    assert triggers(store, 'governance_activity_events') == {'governance_activity_immutable'}
    store.execute(*activity())
    assert_update_refused(store, "UPDATE governance_activity_events SET actor='someone else'")


def test_upgraded_roles_start_their_permissions_revision_at_the_revision(tmp_path):
    """Authority entries use permissions_revision, so an upgrade must not change any saved version."""
    from app.schema_initializers import initialize_enterprise_roles
    store = Store(tmp_path / 'upgrade')
    try:
        store.execute('''CREATE TABLE enterprise_roles (id TEXT PRIMARY KEY, name TEXT NOT NULL,
            description TEXT NOT NULL, permissions TEXT NOT NULL, revision INTEGER NOT NULL,
            archived INTEGER NOT NULL DEFAULT 0, updated_by TEXT NOT NULL, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)''')
        store.execute("INSERT INTO enterprise_roles VALUES('reader','Reader','','[]',4,0,'owner','now','now')")
        initialize_enterprise_roles(store)
        store.execute('UPDATE enterprise_roles SET revision=5')  # A later rename; rerunning must not reset it.
        initialize_enterprise_roles(store)
        assert store.rows('SELECT revision,permissions_revision FROM enterprise_roles') == [
            {'revision': 5, 'permissions_revision': 4}]
    finally:
        store.close()


def test_live_scim_names_are_unique_but_tombstones_are_retained(store):
    stamp = '2026-10-16T00:00:00.000000+00:00'
    user = ('INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision) '
            "VALUES(?,?,?,'{}',?,?,?,?,1)")
    store.execute(user, ('a' * 32, 'entra-1', 'person@example.com', 0, stamp, stamp, stamp))
    store.execute(user, ('b' * 32, 'entra-1', 'person@example.com', 1, '', stamp, stamp))
    with pytest.raises(INTEGRITY_ERRORS):  # A second live userName.
        store.execute(user, ('c' * 32, 'entra-2', 'person@example.com', 1, '', stamp, stamp))
    with pytest.raises(INTEGRITY_ERRORS):  # A second live externalId.
        store.execute(user, ('d' * 32, 'entra-1', 'other@example.com', 1, '', stamp, stamp))
    # Empty external ids are not identities and never collide.
    store.execute(user, ('e' * 32, '', 'second@example.com', 1, '', stamp, stamp))
    store.execute(user, ('f' * 32, '', 'third@example.com', 1, '', stamp, stamp))
    with pytest.raises(INTEGRITY_ERRORS):
        store.execute("INSERT INTO scim_users(id,user_name,profile,active,created_at,updated_at,revision) "
                      "VALUES('g',?,'{}',2,?,?,1)", ('fourth@example.com', stamp, stamp))
    with pytest.raises(INTEGRITY_ERRORS):
        store.execute("INSERT INTO scim_group_members VALUES('missing-group',?)", ('b' * 32,))
    assert store.rows("SELECT id FROM scim_users WHERE user_name='person@example.com' ORDER BY id") == [
        {'id': 'a' * 32}, {'id': 'b' * 32}]


def test_event_is_part_of_the_mutation_transaction(store):
    with pytest.raises(RuntimeError, match='synthetic rollback'), store.connect() as conn:
        conn.begin_write()
        conn.execute("INSERT INTO spend_limits VALUES('organization','organization','',0,1,'owner@example.com','now')")
        event(conn)
        raise RuntimeError('synthetic rollback')
    assert store.rows('SELECT * FROM spend_limits') == []
    assert store.rows('SELECT * FROM governance_audit_events') == []
    with store.connect() as conn:
        with pytest.raises(RuntimeError, match='write transaction'):
            event(conn)
        conn.begin_write()
        identity = event(conn, details={'replacement': 'auditor', 'previous': 'member', 'permissions': ['audit.read']})
    [row] = store.rows('SELECT * FROM governance_audit_events')
    assert row['id'] == identity and re.fullmatch('[0-9a-f]{32}', identity)
    assert row['details'] == '{"permissions":["audit.read"],"previous":"member","replacement":"auditor"}'
    assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00', row['created_at'])
    assert {key: row[key] for key in ('action', 'actor', 'resource_type', 'resource_id')} == {
        'action': 'role.updated', 'actor': 'owner@example.com', 'resource_type': 'CustomRole',
        'resource_id': 'a' * 32}


@pytest.mark.parametrize(('change', 'error'), [
    ({'action': ''}, ValueError), ({'action': 'x' * 65}, ValueError), ({'resource_type': 'x' * 65}, ValueError),
    ({'actor': 'x' * 513}, ValueError), ({'resource_id': 'x' * 513}, ValueError), ({'actor': 'a\x00b'}, ValueError),
    ({'resource_id': 7}, TypeError), ({'details': ['not', 'an', 'object']}, TypeError),
    ({'details': {1: 'numeric key'}}, TypeError), ({'details': {'value': object()}}, TypeError),
    ({'details': {'value': float('nan')}}, ValueError),
    ({'details': {'value': 'x' * MAX_DETAILS_BYTES}}, ValueError),
    ({'details': {'value': 'é' * (MAX_DETAILS_BYTES // 2)}}, ValueError),
])
def test_invalid_events_are_rejected_before_any_write(store, change, error):
    with store.connect() as conn:
        conn.begin_write()
        with pytest.raises(error) as rejected:
            event(conn, **change)
        assert 'x' * 65 not in str(rejected.value) and 'numeric key' not in str(rejected.value)
    assert store.rows('SELECT * FROM governance_audit_events') == []


def test_bounds_are_inclusive(store):
    details = {'value': 'x' * (MAX_DETAILS_BYTES - len(json.dumps({'value': ''}, separators=(',', ':'))))}
    with store.connect() as conn:
        conn.begin_write()
        event(conn, action='a' * 64, resource_type='t' * 64, actor='p' * 512, resource_id='r' * 512, details=details)
    assert len(store.rows('SELECT details FROM governance_audit_events')[0]['details'].encode()) == MAX_DETAILS_BYTES


def test_permission_catalog_keeps_builtin_roles_unchanged():
    assert permissions.BUILTIN_PERMISSIONS['admin'] == frozenset(permissions.PERMISSIONS)
    assert permissions.BUILTIN_PERMISSIONS['member'] is permissions.MEMBER_PERMISSIONS
    assert permissions.MEMBER_PERMISSIONS < frozenset(permissions.PERMISSIONS)
    assert not permissions.MEMBER_PERMISSIONS & {'roles.manage', 'users.manage', 'scim.manage', 'security.manage',
                                                 'audit.read', 'spend.read', 'spend.manage'}
    assert [item['id'] for item in permissions.catalog()] == list(permissions.PERMISSIONS)
    assert all(item['description'] for item in permissions.catalog())
