"""Revision-22 governance storage and audit-event contract on SQLite or --postgres-backend."""
import json
import re

import pytest
from app import permissions
from app.database import INTEGRITY_ERRORS
from app.db import Store
from app.governance_audit import MAX_DETAILS_BYTES, record_event_in
from app.schema_migrations import COMPONENTS, initialize_components

GOVERNANCE = ('enterprise_roles', 'scim', 'security_profiles', 'spend_limits', 'governance_audit')


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
            'security_profile_defaults', 'spend_limits', 'governance_audit_events'} <= store.table_names()


def test_governance_module_initializers_need_only_the_core_store(tmp_path):
    from app import enterprise_roles, governance_audit, scim, security_profiles, spend_limits
    store = Store(tmp_path / 'core-only')
    try:
        # Service constructors may initialize before other components in auto mode.
        for module in (governance_audit, spend_limits, security_profiles, scim, enterprise_roles):
            module.initialize_schema(store)
        assert 'governance_audit_events' in store.table_names()
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
