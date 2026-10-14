from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Store, now
from app.main import create_app
from app.user_roles import RoleChange, UserRoles


@pytest.fixture
def users_app(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='https://workspace.example',
                        google_client_id='test-client', google_client_secret='test-secret',
                        google_allowed_domains='berri.ai', google_admin_emails='tin@berri.ai,ishaan@berri.ai',
                        password_login_enabled=False)
    app = create_app(settings)
    with TestClient(app, base_url=settings.public_url) as client:
        yield app, client


def sign_as(app, client, email):
    response = JSONResponse({})
    sid = app.state.security.new_session(response, identity={
        'sub': email.split('@')[0], 'email': email, 'domain': email.rpartition('@')[2], 'name': email.split('@')[0].title()})
    client.cookies.clear()
    client.cookies.set('workspace_session', response.headers['set-cookie'].split('workspace_session=')[1].split(';')[0])
    client.headers.update({'Origin': app.state.settings.public_url, 'X-CSRF-Token': app.state.security.csrf(sid)})
    return client.get('/api/session').json()


def change(client, email, role, revision=0):
    return client.put('/api/admin/users/role', json={'email': email, 'role': role, 'revision': revision})


def directory_write(app, kind, body, identity=None):
    with app.state.store.connect() as conn:
        conn.begin_write()
        return app.state.scim.write_in(conn, kind, body, identity)


def test_current_admins_preserved_and_role_changes_apply_to_existing_sessions(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    initial = client.get('/api/admin/users').json()['users']
    assert {row['email'] for row in initial if row['role'] == 'admin'} == {'tin@berri.ai', 'ishaan@berri.ai'}
    sign_as(app, client, 'maya@berri.ai')
    member_cookie = dict(client.cookies)
    assert client.get('/api/session').json()['role'] == 'member'
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, ' Maya@Berri.AI ', 'admin').status_code == 200
    admin_cookie = dict(client.cookies)
    client.cookies.clear(); client.cookies.update(member_cookie)
    assert client.get('/api/session').json()['role'] == 'admin'
    assert client.get('/api/admin/users').status_code == 200
    client.cookies.clear(); client.cookies.update(admin_cookie)
    assert change(client, 'maya@berri.ai', 'member', 1).status_code == 200
    client.cookies.clear(); client.cookies.update(member_cookie)
    assert client.get('/api/session').json()['role'] == 'member'
    assert client.get('/api/admin/users').status_code == 403
    assert client.post('/api/approvals/anything', json={'decision': 'approve'}).status_code == 403
    # The audit uses the verified actor identity and records both changes.
    audit = app.state.store.rows('SELECT * FROM user_role_audit ORDER BY id')
    assert [(row['previous_role'], row['role'], row['actor']) for row in audit] == [
        ('member', 'admin', 'tin@berri.ai'), ('admin', 'member', 'tin@berri.ai')]


def test_members_cannot_read_directory_promote_or_spoof_actor(users_app):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/admin/users').status_code == 403
    assert change(client, 'maya@berri.ai', 'admin').status_code == 403
    assert not app.state.store.rows('SELECT * FROM user_roles')
    sign_as(app, client, 'tin@berri.ai')
    spoofed = client.put('/api/admin/users/role', json={
        'email': 'maya@berri.ai', 'role': 'admin', 'revision': 0, 'actor': 'ishaan@berri.ai'})
    assert spoofed.status_code == 422
    client.headers['X-CSRF-Token'] = 'wrong'
    assert change(client, 'maya@berri.ai', 'admin').status_code == 403
    sign_as(app, client, 'tin@berri.ai')
    client.headers['Origin'] = 'https://untrusted.example'
    assert change(client, 'maya@berri.ai', 'admin').status_code == 403
    client.cookies.clear()
    assert client.get('/api/admin/users').status_code == 401
    assert change(client, 'maya@berri.ai', 'admin').status_code == 401


@pytest.mark.parametrize('email,role', [('person@gmail.com', 'admin'), ('bad-address', 'member'),
    ('tin@berri.ai.attacker.example', 'admin'), ('two@@berri.ai', 'member'), ('tin@berri.ai', 'owner')])
def test_rejects_external_addresses_and_unknown_roles(users_app, email, role):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, email, role).status_code == 422
    assert not app.state.store.rows('SELECT * FROM user_roles')


def test_last_admin_protection_and_self_demotion(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, 'ishaan@berri.ai', 'member').status_code == 200
    assert change(client, 'tin@berri.ai', 'member').status_code == 409
    assert client.get('/api/session').json()['role'] == 'admin'
    assert change(client, 'maya@berri.ai', 'admin').status_code == 200
    assert change(client, 'tin@berri.ai', 'member').status_code == 200
    assert client.get('/api/session').json()['role'] == 'member'
    # The same old cookie cannot undo its own demotion.
    assert change(client, 'tin@berri.ai', 'admin', 1).status_code == 403


def test_concurrent_demotions_keep_one_admin(users_app):
    app, _ = users_app
    barrier = Barrier(2)
    def demote(email):
        barrier.wait(timeout=5)
        try:
            app.state.user_roles.change(RoleChange(email=email, role='member', revision=0),
                                        {'method': 'google', 'identity': {'email': email}})
            return 200
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(demote, ['tin@berri.ai', 'ishaan@berri.ai']))
    assert sorted(outcomes) == [200, 409]
    assert len([row for row in app.state.user_roles.directory()['users'] if row['role'] == 'admin']) == 1


@pytest.mark.parametrize('route', ['users', 'assignments'])
def test_deactivated_admin_can_be_demoted_while_another_admin_is_active(users_app, route):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    person = directory_write(app, 'User', {'userName': 'ishaan@berri.ai'})
    directory_write(app, 'User', {'userName': 'ishaan@berri.ai', 'active': False}, person['id'])
    response = change(client, 'ishaan@berri.ai', 'member') if route == 'users' else client.put(
        '/api/admin/role-assignments', json={'email': 'ishaan@berri.ai', 'role_id': 'member', 'revision': 0})
    assert response.status_code == 200, response.text
    # The last active administrator stays protected.
    assert change(client, 'tin@berri.ai', 'member').status_code == 409
    directory_write(app, 'User', {'userName': 'ishaan@berri.ai', 'active': True}, person['id'])
    assert app.state.user_roles.role('ishaan@berri.ai') == 'member'


def test_directory_guard_keeps_promoted_admins_without_configured_admins(tmp_path):
    from app.scim import Scim
    from app.security import Security
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787', google_allowed_domains='berri.ai')
    store = Store(settings.data_dir)
    roles = UserRoles(store, settings)
    directory = Scim(store, Security(settings, roles), roles)

    def write(body, identity=None):
        with store.connect() as conn:
            conn.begin_write()
            return directory.write_in(conn, 'User', body, identity)

    # A local deployment that never had administrators provisions freely.
    maya = write({'userName': 'maya@berri.ai'})
    assert write({'userName': 'maya@berri.ai', 'active': False}, maya['id'])['active'] is False
    local = {'method': 'local', 'role': 'admin'}
    roles.change(RoleChange(email='tin@berri.ai', role='admin', revision=0), local)
    tin = write({'userName': 'tin@berri.ai'})
    with pytest.raises(HTTPException) as error:
        write({'userName': 'tin@berri.ai', 'active': False}, tin['id'])
    assert error.value.status_code == 409
    roles.change(RoleChange(email='ishaan@berri.ai', role='admin', revision=0), local)
    assert write({'userName': 'tin@berri.ai', 'active': False}, tin['id'])['active'] is False


def test_require_actor_resolves_activity_and_group_tables_once(users_app, monkeypatch):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    roles = app.state.user_roles
    checked = []
    active_actor_in = roles.active_actor_in
    monkeypatch.setattr(roles, 'active_actor_in', lambda conn, actor: checked.append(actor) or active_actor_in(conn, actor))
    with roles.store.connect() as conn:
        listed = []
        table_names = conn.table_names
        conn.table_names = lambda: listed.append(1) or table_names()
        roles.enterprise.group_permissions_in(conn, 'maya@berri.ai')
        roles.enterprise.group_permissions_in(conn, 'maya@berri.ai')
        assert len(listed) <= 1  # Once per connection; PostgreSQL caches it per schema.
        roles.require_actor('google:maya', 'sessions.create', connection=conn)
        assert checked == ['google:maya']
        with pytest.raises(HTTPException) as error:
            roles.require_actor('google:maya', 'roles.manage', connection=conn)
        assert error.value.detail == 'Your workspace role does not permit this action.'
    person = directory_write(app, 'User', {'userName': 'maya@berri.ai', 'active': False})
    with pytest.raises(HTTPException) as error:
        roles.require_actor('google:maya', 'sessions.create')
    assert error.value.detail == 'This workspace account has been deactivated.' and not person['active']


def test_concurrent_actor_revocation_is_checked_inside_transaction(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    stale_actor = {'method': 'google', 'identity': {'email': 'ishaan@berri.ai'}}
    assert change(client, 'ishaan@berri.ai', 'member').status_code == 200
    with pytest.raises(HTTPException) as error:
        app.state.user_roles.change(RoleChange(email='maya@berri.ai', role='admin', revision=0), stale_actor)
    assert error.value.status_code == 403


def test_stale_updates_fail_and_saved_demotions_survive_restart(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, 'ishaan@berri.ai', 'member').status_code == 200
    assert change(client, 'ishaan@berri.ai', 'admin', 0).status_code == 409
    # Reopening the durable database must not regrant the environment default.
    restored = UserRoles(Store(app.state.settings.data_dir), app.state.settings)
    assert restored.role('ishaan@berri.ai') == 'member'
    assert restored.role('tin@berri.ai') == 'admin'
    assert len(restored.directory()['activity']) == 1


def test_preassigned_user_must_still_have_verified_allowed_sso(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, 'future@berri.ai', 'admin').status_code == 200
    future = next(row for row in client.get('/api/admin/users').json()['users'] if row['email'] == 'future@berri.ai')
    assert future['role'] == 'admin' and not future['has_signed_in']
    assert not app.state.store.rows("SELECT id FROM users WHERE email='future@berri.ai'")
    client.cookies.clear()
    assert client.get('/api/admin/users').status_code == 401
    assert sign_as(app, client, 'future@berri.ai')['role'] == 'admin'
    app.state.settings.google_allowed_domains = 'another.example'
    assert client.get('/api/runs').status_code == 401


def test_directory_includes_eligible_slack_users_without_changing_spend_links(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    for name, email, eligible in [('maya', 'maya@berri.ai', 1), ('outsider', 'other@example.com', 1), ('guest', 'guest@berri.ai', 0)]:
        app.state.store.execute('INSERT INTO users(id,kind,email,name,created_at,updated_at,profile_eligible) VALUES(?,?,?,?,?,?,?)',
            ('slack:'+name, 'slack', email, name, now(), now(), eligible))
    rows = client.get('/api/admin/users').json()['users']
    assert {row['email'] for row in rows} == {'tin@berri.ai', 'ishaan@berri.ai', 'maya@berri.ai'}
    assert change(client, 'maya@berri.ai', 'admin').status_code == 200
    assert app.state.store.rows("SELECT linked_user_id FROM users WHERE id='slack:maya'")[0]['linked_user_id'] is None
    assert not app.state.store.rows('SELECT * FROM identity_audit')


def test_agent_org_skill_writes_follow_current_user_role(users_app):
    from test_spend import active
    from test_skill_saving import call, form
    app, client = users_app
    sign_as(app, client, 'ishaan@berri.ai')
    run = active(app, 'google:ishaan')
    sign_as(app, client, 'tin@berri.ai')
    assert change(client, 'ishaan@berri.ai', 'member').status_code == 200
    denied = call(client, run, **form(scope='organization'))
    assert denied.status_code == 200 and denied.json()['status_code'] == 403
    assert denied.json()['error']
    assert call(client, run, **form(scope='personal')).status_code == 200
    assert change(client, 'ishaan@berri.ai', 'admin', 1).status_code == 200
    assert call(client, run, **form(scope='organization', request_id='promoted-org-save')).status_code == 200
