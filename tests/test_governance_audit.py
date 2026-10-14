import json

import pytest
from fastapi import HTTPException

from app.governance_audit import GovernanceAudit, record_event_in
from test_enterprise_roles import assign, create_role
from test_user_roles import sign_as, users_app


@pytest.fixture
def audit_app(users_app):
    app, client = users_app
    audit = GovernanceAudit(app.state.store, app.state.security)
    if not any(getattr(route, 'path', '') == '/api/admin/governance/audit' for route in app.routes):
        app.include_router(audit.routes())
    return app, client, audit


def test_audit_reader_can_read_metadata_without_role_or_directory_management(audit_app):
    app, client, _ = audit_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'auditor', ['workspace.read', 'audit.read'])
    assert assign(client, role_id='auditor').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    response = client.get('/api/admin/governance/audit')
    assert response.status_code == 200, response.text
    assert response.json()['events']
    assert all(set(event) == {'id', 'action', 'actor', 'resource_type', 'resource_id', 'created_at'}
               for event in response.json()['events'])
    assert client.get('/api/admin/roles').status_code == 403
    assert client.get('/api/admin/users').status_code == 403
    assert client.get('/api/admin/security-profiles').status_code == 403
    sign_as(app, client, 'ishaan@berri.ai')
    assert client.put('/api/admin/role-assignments', json={
        'email': 'maya@berri.ai', 'role_id': 'member', 'revision': 1}).status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/admin/governance/audit').status_code == 403


def test_feed_merges_sources_and_never_exports_role_content_or_profile_policy(audit_app):
    from app.scim import Scim
    from app.security_profiles import SecurityProfiles
    app, client, _ = audit_app
    sign_as(app, client, 'tin@berri.ai')
    body = {'id': 'private-role', 'name': 'Private', 'description': 'sensitive-role-description',
            'permissions': ['workspace.read'], 'revision': 0}
    assert client.post('/api/admin/roles', json=body).status_code == 201
    assert assign(client, role_id='private-role').status_code == 200
    directory = Scim(app.state.store, app.state.security, app.state.user_roles)
    with app.state.store.connect() as conn:
        conn.begin_write()
        user = directory.write_in(conn, 'User', {'userName': 'future@berri.ai', 'displayName': 'private-profile-text'})
        directory.audit_in(conn, 'test-provisioner', 'user.created', 'User', user['id'])
    profiles = SecurityProfiles(app.state.store)
    profiles.save('private-profile', {'name': 'Private', 'revision': 0,
        'policy': {'network_domains': ['private-network.example']}}, 'tin@berri.ai')
    profiles.save_defaults({'revision': 0, 'default_profile_id': 'private-profile'}, 'tin@berri.ai')
    response = client.get('/api/admin/governance/audit')
    assert response.status_code == 200, response.text
    events = response.json()['events']
    assert {'role.created', 'assignment.updated', 'user.created', 'security.profile.updated', 'security.defaults.updated'} <= {
        event['action'] for event in events}
    assert 'sensitive-role-description' not in response.text
    assert 'private-profile-text' not in response.text
    assert 'private-network.example' not in response.text
    assert all('policy' not in event and 'permissions' not in event for event in events)


def test_signed_snapshot_cursor_stays_stable_across_new_and_backdated_commits(audit_app):
    app, _, audit = audit_app
    with app.state.store.connect() as conn:
        conn.begin_write()
        for index in range(7):
            record_event_in(conn, 'test.event', 'tester', 'Test', str(index))
    first = audit.listing(limit=2)
    assert first['next_cursor']
    baseline = audit.listing(limit=100)['events']
    with app.state.store.connect() as conn:
        conn.begin_write()
        identity = record_event_in(conn, 'test.late-commit', 'tester', 'Test', 'late')
        # Timestamp ordering alone would let a late commit enter an older page.
        conn.execute('UPDATE governance_audit_events SET created_at=? WHERE id=?', ('2000-01-01T00:00:00+00:00', identity))
    events = list(first['events'])
    cursor = first['next_cursor']
    while cursor:
        page = audit.listing(cursor, limit=2)
        events.extend(page['events'])
        cursor = page['next_cursor']
    assert events == baseline
    assert len({event['id'] for event in events}) == len(events)
    assert audit.listing(limit=100)['events'][0]['action'] == 'test.late-commit'
    # An old cursor can be retried with exactly the same committed snapshot.
    assert audit.listing(first['next_cursor'], 2)['events'] == audit.listing(first['next_cursor'], 2)['events']


def test_cursor_pages_read_their_snapshot_without_writer_lock_or_rescan(audit_app, monkeypatch):
    from app.database import PostgresConnection, SQLiteConnection
    app, _, audit = audit_app
    with app.state.store.connect() as conn:
        conn.begin_write()
        for index in range(3):
            record_event_in(conn, 'test.event', 'tester', 'Test', str(index))
    first = audit.listing(limit=1)
    with app.state.store.connect() as conn:
        conn.begin_write()
        record_event_in(conn, 'test.late-commit', 'tester', 'Test', 'late')
    import threading
    writes, reader = [], threading.get_ident()
    for kind in (SQLiteConnection, PostgresConnection):
        # Count only this caller's transactions; background pollers also write.
        monkeypatch.setattr(kind, 'begin_write', lambda self, original=kind.begin_write: (
            threading.get_ident() == reader and writes.append(self)) or original(self))
    monkeypatch.setattr(audit, 'index_in', lambda conn: pytest.fail('A cursor page rescanned every audit source'))
    second = audit.listing(first['next_cursor'], 1)
    third = audit.listing(second['next_cursor'], 1)
    assert not writes and third['next_cursor'] is None
    assert sorted(event['resource_id'] for page in (first, second, third) for event in page['events']) == ['0', '1', '2']


def test_invalid_cursors_and_uncommitted_changes_never_enter_the_feed(audit_app):
    app, _, audit = audit_app
    with pytest.raises(RuntimeError):
        with app.state.store.connect() as conn:
            conn.begin_write()
            record_event_in(conn, 'test.rolled-back', 'tester', 'Test', 'discarded')
            raise RuntimeError('abort transaction')
    assert not audit.listing()['events']
    for value in ('not-a-cursor', audit.cursor(2, 4), app.state.security.signer.dumps({'v': 1, 'cap': True, 'before': 1}, salt='governance-audit-v1')):
        with pytest.raises(HTTPException) as error:
            audit.listing(value)
        assert error.value.status_code == 422
    assert not app.state.store.rows('SELECT * FROM governance_audit_index')


def test_security_defaults_mutations_commit_their_audit_atomically(audit_app):
    from app.security_profiles import SecurityProfiles
    app, _, audit = audit_app
    profiles = SecurityProfiles(app.state.store)
    profiles.save_defaults({'revision': 0}, 'policy-owner@berri.ai')
    assert app.state.store.rows('SELECT actor FROM governance_audit_events') == [{'actor': 'policy-owner@berri.ai'}]
    with pytest.raises(HTTPException):
        profiles.save_defaults({'revision': 0}, 'rejected-editor@berri.ai')
    defaults = [event for event in audit.listing()['events'] if event['action'] == 'security.defaults.updated']
    assert len(defaults) == 1 and defaults[0]['actor'] == 'policy-owner@berri.ai'
    assert 'rejected-editor' not in json.dumps(defaults)
