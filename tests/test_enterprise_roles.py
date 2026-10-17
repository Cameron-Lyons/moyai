"""Custom roles must affect existing sessions and survive every access path."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, get_ident

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.enterprise_roles import ADMIN_ONLY, RoleAssignment, RoleDefinition
from app.permissions import BUILTIN_PERMISSIONS, MEMBER_PERMISSIONS
from test_user_roles import directory_write, sign_as, users_app

AMPLIFY = 'You can only grant permissions you hold.'


def create_role(client, identity='reader', permissions=None):
    response = client.post('/api/admin/roles', json={
        'id': identity, 'name': identity.title(), 'description': 'Reviewed workspace role',
        'permissions': permissions if permissions is not None else ['workspace.read', 'sessions.read'], 'revision': 0})
    assert response.status_code == 201, response.text
    return response.json()


def assign(client, email='maya@berri.ai', role_id='reader', revision=0):
    return client.put('/api/admin/role-assignments', json={'email': email, 'role_id': role_id, 'revision': revision})


def test_role_handlers_query_the_database_off_the_event_loop(users_app, monkeypatch):
    import asyncio
    from contextvars import ContextVar
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    group = directory_write(app, 'Group', {'displayName': 'Off-loop reviewers'})
    current_request = ContextVar('governance_database_request', default=None)
    borrows, original_require, original_connect = [], app.state.security.require, app.state.store.connect

    def require(request, *args, **kwargs):
        current_request.set((request.method, request.scope['path']))
        return original_require(request, *args, **kwargs)

    def connect(*args, **kwargs):
        if identity := current_request.get():
            try:
                running = bool(asyncio.get_running_loop())
            except RuntimeError:
                running = False
            borrows.append((identity, running))
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(app.state.security, 'require', require)
    monkeypatch.setattr(app.state.store, 'connect', connect)
    definition = {'id': 'off-loop', 'name': 'Off-loop', 'permissions': ['workspace.read'], 'revision': 0}
    requests = [
        ('GET', '/api/permissions', {}, 200),
        ('GET', '/api/admin/roles', {}, 200),
        ('POST', '/api/admin/roles', {'json': definition}, 201),
        ('PUT', '/api/admin/roles/off-loop', {'json': {**definition, 'revision': 1}}, 200),
        ('PUT', '/api/admin/role-assignments', {'json': {'email': 'maya@berri.ai', 'role_id': 'off-loop', 'revision': 0}}, 200),
        ('PUT', '/api/admin/group-roles/' + group['id'], {'json': {'role_id': 'off-loop', 'revision': 0}}, 200),
        ('DELETE', '/api/admin/roles/off-loop?revision=2', {}, 200),
    ]
    for method, path, kwargs, status in requests:
        response = client.request(method, path, **kwargs)
        assert response.status_code == status, response.text
    assert {identity for identity, _ in borrows} == {(method, path.split('?')[0]) for method, path, _, _ in requests}
    assert not any(running for _, running in borrows)


def test_custom_assignment_updates_existing_cookie_and_is_an_allowlist(users_app):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    member_cookie = dict(client.cookies)
    assert set(client.get('/api/session').json()['permissions']) == MEMBER_PERMISSIONS
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    assert assign(client).status_code == 200
    client.cookies.clear(); client.cookies.update(member_cookie)
    assert client.get('/api/session').json()['role'] == 'member'
    assert set(client.get('/api/permissions').json()['permissions']) == {'workspace.read', 'sessions.read'}
    assert client.get('/api/runs').status_code == 200
    assert client.get('/api/runs?scope=all').status_code == 403
    assert client.get('/api/connections').status_code == 403
    assert client.post('/api/runs', json={'prompt': 'Do work', 'mode': 'demo'}).status_code == 403
    assert client.get('/api/admin/users').status_code == 403
    assert client.get('/api/admin/spend').status_code == 403
    assert client.get('/api/skills').status_code == 403


def test_delegated_permission_opens_only_its_admin_surface(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'directory-reader', ['workspace.read', 'users.read'])
    assert assign(client, role_id='directory-reader').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/admin/users').status_code == 200
    assert client.put('/api/admin/users/role', json={'email': 'maya@berri.ai', 'role': 'admin', 'revision': 1}).status_code == 403
    assert client.get('/api/admin/roles').status_code == 403
    assert client.get('/api/admin/spend').status_code == 403
    # A future, unmapped admin endpoint must retain the original admin boundary.
    request = Request({'type': 'http', 'method': 'GET', 'path': '/api/admin/future-feature',
                       'headers': [(b'cookie', ('workspace_session=' + client.cookies['workspace_session']).encode())]})
    with pytest.raises(HTTPException) as error:
        app.state.security.require(request, admin=True)
    assert error.value.status_code == 403


@pytest.mark.parametrize('permissions,expected', [
    (['sessions.read'], 403),
    (['connections.read'], 403),
    (['sessions.read', 'connections.read'], 200),
])
def test_native_pr_reader_requires_session_and_connection_read(users_app, monkeypatch, permissions, expected):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = app.state.store.create_run('Read a delivered PR', '', 'demo', [], user_id='google:maya')
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'pr-reader', permissions)
    assert assign(client, role_id='pr-reader').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    calls = []

    async def read(*args, **kwargs):
        calls.append((args, kwargs))
        return {'number': 100, 'files': [{'filename': 'private.py', 'patch': 'private code'}]}

    monkeypatch.setattr(app.state.session_pull_requests, 'read', read)
    response = client.get(f"/api/runs/{run['id']}/pull-request", params={'url': 'https://github.com/org/repo/pull/100'})
    assert response.status_code == expected, response.text
    assert len(calls) == int(expected == 200)
    if expected != 200:
        assert 'private code' not in response.text


@pytest.mark.parametrize('revocation', ['sessions.read', 'connections.read', 'deactivate'])
def test_native_pr_reader_discards_data_when_access_is_revoked_during_read(users_app, monkeypatch, revocation):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = app.state.store.create_run('Read a delivered PR', '', 'demo', [], user_id='google:maya')
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'pr-reader', ['sessions.read', 'connections.read'])
    assert assign(client, role_id='pr-reader').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    calls = []

    async def read(*args, **kwargs):
        calls.append((args, kwargs))
        if revocation == 'deactivate':
            directory_write(app, 'User', {'userName': 'maya@berri.ai', 'active': False})
        else:
            app.state.user_roles.enterprise.save(RoleDefinition(
                id=role['id'], name=role['name'], description=role['description'],
                permissions=[permission for permission in role['permissions'] if permission != revocation],
                revision=role['revision']),
                {'method': 'google', 'identity': {'email': 'tin@berri.ai'}}, role['id'])
        return {'number': 100, 'files': [{'filename': 'private.py', 'patch': 'private code'}]}

    monkeypatch.setattr(app.state.session_pull_requests, 'read', read)
    response = client.get(f"/api/runs/{run['id']}/pull-request", params={'url': 'https://github.com/org/repo/pull/100'})
    assert response.status_code == (401 if revocation == 'deactivate' else 403), response.text
    assert len(calls) == 1
    assert 'private code' not in response.text


def test_delegated_spend_reader_gets_organization_report_and_live_revocation(users_app):
    from test_spend import active
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    for user, cost in [('google:maya', '2'), ('google:tin', '3')]:
        run = active(app, user)
        identity = app.state.spend.begin(run, run['model'])
        app.state.store.execute("UPDATE model_requests SET cost=?,status='completed' WHERE id=?", (cost, identity))
    personal = client.get('/api/spend').json()
    assert personal['total']['spend'] == '2'
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'finance-reader', ['workspace.read', 'spend.read'])
    assert assign(client, role_id='finance-reader').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/session').json()['role'] == 'member'
    for route in ('/api/spend', '/api/admin/spend'):
        response = client.get(route)
        assert response.status_code == 200, response.text
        assert response.json()['total']['spend'] == '5'
        assert {row['id'] for row in response.json()['users']} >= {'google:maya', 'google:tin'}
    assert client.get('/api/admin/roles').status_code == 403
    sign_as(app, client, 'tin@berri.ai')
    update = {key: role[key] for key in ('id', 'name', 'description', 'permissions', 'revision')}
    update['permissions'] = ['workspace.read']
    assert client.put('/api/admin/roles/finance-reader', json=update).status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/spend').status_code == 403
    assert client.get('/api/admin/spend').status_code == 403


def test_builtin_member_permissions_do_not_bypass_scope_specific_admin_checks(users_app):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/runs').status_code == 200
    assert client.get('/api/runs?scope=all').status_code == 403
    assert client.get('/api/admin/spend').status_code == 403
    assert client.get('/api/connections/slack/personal').status_code == 200


def test_custom_role_revision_archive_and_builtin_reset_revoke_immediately(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'operator', ['workspace.read', 'connections.read', 'connections.manage'])
    assert assign(client, role_id='operator').status_code == 200
    assert assign(client, role_id='member').status_code == 409
    update = {key: role[key] for key in ('id', 'name', 'description', 'permissions', 'revision')}
    update['permissions'] = ['workspace.read']
    assert client.put('/api/admin/roles/operator', json=update).status_code == 200
    assert client.put('/api/admin/roles/operator', json=update).status_code == 409
    assert app.state.user_roles.permissions('maya@berri.ai') == {'workspace.read'}
    assert client.delete('/api/admin/roles/operator?revision=1').status_code == 409
    assert client.delete('/api/admin/roles/operator?revision=2').status_code == 200
    assert app.state.user_roles.permissions('maya@berri.ai') == set()
    # The legacy built-in role editor can deliberately remove a custom assignment.
    assert client.put('/api/admin/users/role', json={'email': 'maya@berri.ai', 'role': 'member', 'revision': 1}).status_code == 200
    assert app.state.user_roles.permissions('maya@berri.ai') == MEMBER_PERMISSIONS
    assert assign(client, role_id='operator', revision=2).status_code == 422
    audit = app.state.store.rows('SELECT action,actor FROM enterprise_role_audit')
    assert {'role.created', 'role.updated', 'role.archived', 'assignment.updated'} <= {row['action'] for row in audit}
    assert {row['actor'] for row in audit} == {'tin@berri.ai'}


def test_catalog_validation_csrf_and_reserved_roles(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    body = {'id': 'admin', 'name': 'Bad', 'permissions': ['sessions.read']}
    assert client.post('/api/admin/roles', json=body).status_code == 422
    body.update(id='reader', permissions=['invented.permission'])
    assert client.post('/api/admin/roles', json=body).status_code == 422
    body['permissions'] = []
    client.headers['X-CSRF-Token'] = 'invalid'
    assert client.post('/api/admin/roles', json=body).status_code == 403
    assert not app.state.store.rows('SELECT * FROM enterprise_roles')
    sign_as(app, client, 'tin@berri.ai')
    assert client.delete('/api/admin/roles/admin?revision=0').status_code == 422
    assert assign(client, email='outside@example.com', role_id='member').status_code == 422


def test_custom_assignment_preserves_last_admin_even_with_concurrent_demotions(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    barrier = Barrier(2)

    def demote(email):
        barrier.wait(timeout=5)
        try:
            app.state.user_roles.enterprise.assign(RoleAssignment(email=email, role_id='reader'),
                {'method': 'google', 'identity': {'email': email}})
            return 200
        except HTTPException as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(demote, ['tin@berri.ai', 'ishaan@berri.ai']))
    assert sorted(outcomes) == [200, 409]
    with app.state.store.connect() as conn:
        assert len(app.state.user_roles.admins_in(conn)) == 1


def test_group_grants_use_active_directory_membership_and_revoke_live(users_app):
    from app.scim import Scim
    app, client = users_app
    directory = Scim(app.state.store, app.state.security, app.state.user_roles)
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    create_role(client, 'connection-manager', ['connections.read', 'connections.manage'])
    assert assign(client).status_code == 200
    with app.state.store.connect() as conn:
        conn.begin_write()
        user = directory.write_in(conn, 'User', {'userName': 'maya@berri.ai', 'active': True})
        group = directory.write_in(conn, 'Group', {'displayName': 'Connection managers', 'members': [{'value': user['id']}]})
    mapped = client.put('/api/admin/group-roles/' + group['id'], json={'role_id': 'connection-manager', 'revision': 0})
    assert mapped.status_code == 200, mapped.text
    assert app.state.user_roles.permissions('maya@berri.ai') == {'workspace.read', 'sessions.read', 'connections.read', 'connections.manage'}
    assert client.put('/api/admin/group-roles/' + group['id'], json={'role_id': 'admin', 'revision': 1}).status_code == 422
    with app.state.store.connect() as conn:
        conn.begin_write()
        directory.write_in(conn, 'Group', {'displayName': 'Connection managers', 'members': []}, group['id'])
    assert app.state.user_roles.permissions('maya@berri.ai') == {'workspace.read', 'sessions.read'}
    with app.state.store.connect() as conn:
        conn.begin_write()
        directory.write_in(conn, 'User', {'userName': 'maya@berri.ai', 'active': False}, user['id'])
    assert app.state.user_roles.permissions('maya@berri.ai') == set()
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/runs').status_code == 401


def test_agent_skill_publishing_uses_custom_permissions_and_revocation(users_app):
    from test_spend import active
    from test_skill_saving import call, form
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = active(app, 'google:maya')
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'skill-publisher', sorted(MEMBER_PERMISSIONS | {'skills.publish'}))
    assert assign(client, role_id='skill-publisher').status_code == 200
    assert call(client, run, **form(scope='organization', request_id='custom-publisher')).json().get('saved')
    role = next(row for row in client.get('/api/admin/roles').json()['roles'] if row['id'] == 'skill-publisher')
    update = {key: role[key] for key in ('id', 'name', 'description', 'permissions', 'revision')}
    update['permissions'] = sorted(MEMBER_PERMISSIONS)
    assert client.put('/api/admin/roles/skill-publisher', json=update).status_code == 200
    denied = call(client, run, **form(scope='organization', request_id='revoked-publisher'))
    assert denied.status_code == 200 and denied.json()['status_code'] == 403


def test_delegated_actor_cannot_keep_stale_role_manager_authority(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'role-manager', ['workspace.read', 'roles.manage'])
    assert assign(client, role_id='role-manager').status_code == 200
    stale = {'method': 'google', 'identity': {'email': 'maya@berri.ai'}}
    assert assign(client, role_id='member', revision=1).status_code == 200
    with pytest.raises(HTTPException) as error:
        app.state.user_roles.enterprise.save(RoleDefinition(id='unapproved', name='Bad', permissions=[]), stale)
    assert error.value.status_code == 403
    assert app.state.user_roles.permissions('tin@berri.ai') == BUILTIN_PERMISSIONS['admin']


def test_shared_runtime_actors_follow_current_auth_configuration(users_app):
    app, _ = users_app
    roles = app.state.user_roles
    settings = roles.settings
    settings.password_login_enabled = True
    settings.workspace_password = 'test-only-shared-admin-password'
    settings.workspace_member_password = 'test-only-shared-member-password'
    with roles.store.connect() as conn:
        assert roles.permissions_for_actor_in(conn, 'shared:password:admin') == BUILTIN_PERMISSIONS['admin']
        assert roles.permissions_for_actor_in(conn, 'shared:password:member') == MEMBER_PERMISSIONS
        assert not roles.permissions_for_actor_in(conn, 'shared:invented:admin')
        assert not roles.permissions_for_actor_in(conn, 'shared:password:owner')
        assert not roles.permissions_for_actor_in(conn, 'shared:password:extra:admin')
    settings.password_login_enabled = False
    with roles.store.connect() as conn:
        assert not roles.permissions_for_actor_in(conn, 'shared:password:admin')
        assert not roles.permissions_for_actor_in(conn, 'shared:password:member')
        assert not roles.permissions_for_actor_in(conn, 'shared:local:admin')
    settings.public_url = 'http://127.0.0.1:8787'
    settings.workspace_password = ''
    settings.google_client_id = ''
    settings.google_client_secret = ''
    with roles.store.connect() as conn:
        assert roles.permissions_for_actor_in(conn, 'shared:local:admin') == BUILTIN_PERMISSIONS['admin']
    settings.public_url = 'https://workspace.example'
    with roles.store.connect() as conn:
        assert not roles.permissions_for_actor_in(conn, 'shared:local:admin')


def test_custom_all_permissions_do_not_grant_builtin_ownership_override(users_app):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'all-capabilities', sorted(BUILTIN_PERMISSIONS['admin']))
    assert assign(client, role_id='all-capabilities').status_code == 200
    with app.state.store.connect() as conn:
        assert app.state.user_roles.is_admin_actor_in(conn, 'google:tin')
        assert not app.state.user_roles.is_admin_actor_in(conn, 'google:maya')
        assert not app.state.user_roles.is_admin_actor_in(conn, 'google:unknown')
        assert not app.state.user_roles.is_admin_actor_in(conn, 'shared:invented:admin')


def test_delegates_cannot_grant_administrator_or_permissions_they_lack(users_app):
    app, client = users_app
    for email in ('maya@berri.ai', 'ops@berri.ai'):
        sign_as(app, client, email)
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    create_role(client, 'user-admin', ['workspace.read', 'users.read', 'users.manage'])
    create_role(client, 'role-manager', sorted(MEMBER_PERMISSIONS | {'roles.manage'}))
    assert assign(client, role_id='user-admin').status_code == 200
    assert assign(client, email='ops@berri.ai', role_id='role-manager').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    for email, role, revision in [('maya@berri.ai', 'admin', 1), ('ishaan@berri.ai', 'member', 0)]:
        denied = client.put('/api/admin/users/role', json={'email': email, 'role': role, 'revision': revision})
        assert denied.status_code == 403 and denied.json()['detail'] == ADMIN_ONLY
    denied = client.put('/api/admin/users/role', json={'email': 'new@berri.ai', 'role': 'member', 'revision': 0})
    assert denied.status_code == 403 and denied.json()['detail'] == AMPLIFY
    sign_as(app, client, 'ops@berri.ai')
    for email, role_id, revision in [('ops@berri.ai', 'admin', 1), ('tin@berri.ai', 'reader', 0)]:
        denied = assign(client, email=email, role_id=role_id, revision=revision)
        assert denied.status_code == 403 and denied.json()['detail'] == ADMIN_ONLY
    denied = client.post('/api/admin/roles', json={'id': 'auditor', 'name': 'Auditor', 'permissions': ['audit.read']})
    assert denied.status_code == 403 and denied.json()['detail'] == AMPLIFY
    own = next(row for row in client.get('/api/admin/roles').json()['roles'] if row['id'] == 'role-manager')
    widened = {key: own[key] for key in ('id', 'name', 'description', 'revision')} | {'permissions': own['permissions'] + ['spend.read']}
    assert client.put('/api/admin/roles/role-manager', json=widened).json()['detail'] == AMPLIFY
    assert assign(client, email='new@berri.ai', role_id='user-admin').json()['detail'] == AMPLIFY
    assert assign(client, email='new@berri.ai').status_code == 200
    assert assign(client, email='new@berri.ai', role_id='member', revision=1).status_code == 200
    assert {app.state.user_roles.role(email) for email in ('maya@berri.ai', 'ops@berri.ai', 'new@berri.ai')} == {'member'}
    assert app.state.user_roles.role('tin@berri.ai') == app.state.user_roles.role('ishaan@berri.ai') == 'admin'
    with app.state.store.connect() as conn:
        assert not app.state.user_roles.is_admin_actor_in(conn, 'google:maya')
        assert not app.state.user_roles.is_admin_actor_in(conn, 'google:ops')


def test_group_granted_governance_cannot_become_administrator(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'finance-reader', ['workspace.read', 'spend.read'])
    create_role(client, 'governance-ops', ['workspace.read', 'users.read', 'users.manage', 'roles.manage'])
    person = directory_write(app, 'User', {'userName': 'maya@berri.ai'})
    group = directory_write(app, 'Group', {'displayName': 'IT', 'members': [{'value': person['id']}]})
    assert client.put('/api/admin/group-roles/' + group['id'], json={'role_id': 'governance-ops', 'revision': 0}).status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert {'users.manage', 'roles.manage'} <= set(client.get('/api/permissions').json()['permissions'])
    denied = client.put('/api/admin/users/role', json={'email': 'maya@berri.ai', 'role': 'admin', 'revision': 0})
    assert denied.status_code == 403 and denied.json()['detail'] == ADMIN_ONLY
    denied = assign(client, role_id='admin')
    assert denied.status_code == 403 and denied.json()['detail'] == ADMIN_ONLY
    # A group grant cannot be widened beyond what the granting delegate holds.
    denied = client.put('/api/admin/group-roles/' + group['id'], json={'role_id': 'finance-reader', 'revision': 1})
    assert denied.status_code == 403 and denied.json()['detail'] == AMPLIFY
    assert client.get('/api/session').json()['role'] == 'member'
    assert app.state.store.rows('SELECT role_id FROM enterprise_group_roles')[0]['role_id'] == 'governance-ops'


def test_role_listing_exposes_live_groups_to_role_managers(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert client.get('/api/admin/roles').json()['groups'] == []
    create_role(client)
    create_role(client, 'role-manager', ['workspace.read', 'sessions.read', 'roles.manage'])
    assert assign(client, role_id='role-manager').status_code == 200
    people = [directory_write(app, 'User', {'userName': name + '@berri.ai'}) for name in ('ava', 'ben')]
    engineering = directory_write(app, 'Group', {'displayName': 'Engineering', 'members': [{'value': row['id']} for row in people]})
    alumni = directory_write(app, 'Group', {'displayName': 'alumni'})
    removed = directory_write(app, 'Group', {'displayName': 'Removed', 'members': [{'value': people[0]['id']}]})
    app.state.store.execute('UPDATE scim_groups SET deleted_at=? WHERE id=?', ('2026-01-01T00:00:00Z', removed['id']))
    sign_as(app, client, 'maya@berri.ai')
    listing = client.get('/api/admin/roles')
    assert listing.status_code == 200
    assert listing.json()['groups'] == [{'id': alumni['id'], 'display_name': 'alumni', 'members': 0},
                                        {'id': engineering['id'], 'display_name': 'Engineering', 'members': 2}]
    assert client.get('/api/admin/scim').status_code == 403
    granted = client.put('/api/admin/group-roles/' + engineering['id'], json={'role_id': 'reader', 'revision': 0})
    assert granted.status_code == 200, granted.text
    assert client.get('/api/admin/roles').json()['group_roles'] == [
        {'group_id': engineering['id'], 'role_id': 'reader', 'revision': 1}]


def test_users_editor_keeps_custom_roles_unless_actor_manages_roles(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    create_role(client, 'user-admin', sorted(MEMBER_PERMISSIONS | {'users.read', 'users.manage'}))
    create_role(client, 'access-admin', sorted(MEMBER_PERMISSIONS | {'users.read', 'users.manage', 'roles.manage'}))
    assert assign(client).status_code == 200
    assert assign(client, email='ops@berri.ai', role_id='user-admin').status_code == 200
    assert assign(client, email='lead@berri.ai', role_id='access-admin').status_code == 200
    unchanged = {'email': 'maya@berri.ai', 'role': 'member', 'revision': 1}
    sign_as(app, client, 'ops@berri.ai')
    denied = client.put('/api/admin/users/role', json=unchanged)
    assert denied.status_code == 403
    assert denied.json()['detail'] == 'This person has a custom workspace role. Change it under Governance → Roles.'
    assert app.state.user_roles.permissions('maya@berri.ai') == {'workspace.read', 'sessions.read'}
    assert client.put('/api/admin/users/role', json={'email': 'new@berri.ai', 'role': 'member', 'revision': 0}).status_code == 200
    sign_as(app, client, 'lead@berri.ai')
    assert client.put('/api/admin/users/role', json=unchanged).status_code == 200
    assert app.state.user_roles.permissions('maya@berri.ai') == MEMBER_PERMISSIONS


def test_directory_matches_live_permission_resolution_in_bulk(users_app, monkeypatch):
    from app import db
    app, client = users_app
    roles = app.state.user_roles
    for email in ('maya@berri.ai', 'mo@berri.ai', 'old@berri.ai', 'grace@berri.ai', 'dan@berri.ai'):
        sign_as(app, client, email)
    sign_as(app, client, 'tin@berri.ai')
    create_role(client)
    create_role(client, 'retired', ['workspace.read', 'spend.read'])
    create_role(client, 'connection-manager', ['connections.read', 'connections.manage'])
    assert assign(client).status_code == 200
    assert assign(client, email='old@berri.ai', role_id='retired').status_code == 200
    assert client.delete('/api/admin/roles/retired?revision=1').status_code == 200
    grace, dan, ishaan = (directory_write(app, 'User', {'userName': name + '@berri.ai'}) for name in ('grace', 'dan', 'ishaan'))
    group = directory_write(app, 'Group', {'displayName': 'Connectors', 'members': [{'value': grace['id']}, {'value': dan['id']}]})
    assert client.put('/api/admin/group-roles/' + group['id'], json={'role_id': 'connection-manager', 'revision': 0}).status_code == 200
    for person in (dan, ishaan):
        directory_write(app, 'User', {'userName': person['userName'], 'active': False}, person['id'])
    rows = {row['email']: row for row in roles.directory()['users']}
    with app.state.store.connect() as conn:
        for email, row in rows.items():
            assert set(row['permissions']) == roles.permissions_in(conn, email), email
            assert (row['role'], row['active']) == (roles.role_in(conn, email), roles.active_email_in(conn, email)), email
    assert set(rows['grace@berri.ai']['permissions']) == MEMBER_PERMISSIONS | {'connections.manage'}
    assert rows['ishaan@berri.ai']['role'] == 'admin' and not rows['ishaan@berri.ai']['permissions']
    assert rows['old@berri.ai']['access_role_id'] == 'retired' and not rows['old@berri.ai']['permissions']
    assert not rows['dan@berri.ai']['active'] and set(rows['tin@berri.ai']['permissions']) == BUILTIN_PERMISSIONS['admin']
    statements, caller, connect = [], get_ident(), db.sqlite_connection

    def traced(path):
        conn = connect(path)
        # Background workers share the store; count only this thread's directory reads.
        if get_ident() == caller:
            conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(db, 'sqlite_connection', traced)

    def cost():
        statements.clear()
        roles.directory()
        return len(statements)

    baseline = cost()
    for index in range(20):
        app.state.store.execute('INSERT INTO user_roles VALUES(?,?,?,?,?)', (f'p{index}@berri.ai', 'member', 1, 'test', 'now'))
    assert cost() == baseline


def test_every_current_broker_tool_has_an_explicit_permission():
    from app.agents import TOOLS as AGENTS
    from app.automation_tools import SPECS as AUTOMATIONS
    from app.connectors import TOOLS as CONNECTORS
    from app.credentials import TOOLS as CREDENTIALS
    from app.media_shares import TOOLS as MEDIA
    from app.memory import TOOL_NAMES as MEMORY
    from app.model_tools import SPECS as MODELS
    from app.permissions import PERMISSIONS, tool_permission
    from app.published_artifacts import SPECS as ARTIFACTS
    from app.skills import TOOL_NAMES as SKILLS
    names = (set(AGENTS) | set(AUTOMATIONS) | set(CONNECTORS) | set(CREDENTIALS)
             | set(MEDIA) | MEMORY | set(MODELS) | set(ARTIFACTS) | SKILLS
             | {'sessions_read', 'sessions_search', 'history_read', 'goal',
                'workspace_diagnostics', 'computer_handoff', 'computer_operation_read',
                'automation_claim_item', 'slack_context', 'slack_participation'})
    assert {name for name in names if tool_permission(name) not in PERMISSIONS} == set()
    assert tool_permission('future_unknown_capability') is None


def test_runtime_capability_does_not_restore_removed_role_permissions(users_app):
    from test_spend import active
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = active(app, 'google:maya')
    headers = {'Authorization': 'Bearer capability'}
    route = f"/broker/{run['id']}/tools"
    baseline = {tool['name'] for tool in client.get(route, headers=headers).json()}
    assert {'sessions_search', 'automation_create', 'model_list', 'history_read'} <= baseline
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'runner', ['sessions.create'])
    assert assign(client, role_id='runner').status_code == 200
    removed = {'sessions_read', 'sessions_search', 'history_read', 'model_list',
               'model_switch', 'workspace_diagnostics', 'goal', 'computer_handoff',
               'artifact_publish', 'artifacts_list', 'media_list', 'media_share',
               'automation_list', 'automation_create', 'automation_environments',
               'skills_search', 'skills_save', 'memory_search', 'memory_save',
               'credentials_list', 'linear_comment', 'slack_personal_search'}
    listed = client.get(route, headers=headers)
    assert listed.status_code == 200, listed.text
    assert not removed & {tool['name'] for tool in listed.json()}
    for name in sorted(removed):
        denied = client.post(route + '/call', headers=headers, json={'name': name, 'arguments': {}})
        assert denied.status_code == 403, (name, denied.text)
    update = {key: role[key] for key in ('id', 'name', 'description', 'permissions', 'revision')}
    update['permissions'] = ['sessions.create', 'sessions.read']
    role = client.put('/api/admin/roles/runner', json=update).json()
    assert 'sessions_search' in {tool['name'] for tool in client.get(route, headers=headers).json()}
    result = client.post(route + '/call', headers=headers,
                         json={'name': 'sessions_search', 'arguments': {'query': 'nonexistent-fixture-keyword'}})
    assert result.status_code == 200 and result.json()['sessions'] == []
    update.update(permissions=['sessions.create'], revision=role['revision'])
    assert client.put('/api/admin/roles/runner', json=update).status_code == 200
    assert client.post(route + '/call', headers=headers,
        json={'name': 'sessions_search', 'arguments': {'query': 'nonexistent-fixture-keyword'}}).status_code == 403


def test_durable_dispatch_revalidates_named_role_before_recording_receipt(users_app):
    from types import SimpleNamespace
    from app.tool_dispatch import ToolDispatch, ToolRejected
    from test_spend import active
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = active(app, 'google:maya')
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'reader-runner', ['sessions.create', 'sessions.read'])
    assert assign(client, role_id='reader-runner').status_code == 200
    dispatch = ToolDispatch(app.state.store, run, SimpleNamespace(
        name='sessions_search', arguments={'query': 'fixture'},
        request_id='a' * 32, input_id=run['active_message_id']))
    update = {key: role[key] for key in ('id', 'name', 'description', 'permissions', 'revision')}
    update['permissions'] = ['sessions.create']
    assert client.put('/api/admin/roles/reader-runner', json=update).status_code == 200
    with pytest.raises(ToolRejected) as error:
        dispatch.claim()
    assert error.value.status_code == 403
    assert app.state.store.rows("SELECT 1 FROM events WHERE run_id=? AND kind='tool_dispatch'", (run['id'],)) == []


def test_raw_broker_routes_obey_the_same_role_permissions(users_app, monkeypatch):
    from test_spend import active
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = active(app, 'google:maya')
    app.state.store.execute('UPDATE runs SET plugins=? WHERE id=?', ('["github"]', run['id']))
    monkeypatch.setattr(app.state.connectors, 'allowed', lambda *a, **kw: True)

    async def unauthorized_target(*args, **kwargs):
        pytest.fail('A role without connections.read reached GitHub repository resolution.')

    monkeypatch.setattr(app.state.connectors.github, 'selected_target', unauthorized_target)
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'only-run', ['sessions.create'])
    assert assign(client, role_id='only-run').status_code == 200
    headers = {'Authorization': 'Bearer capability'}
    base = f"/broker/{run['id']}"
    for suffix in ('/artifacts/transfer', '/goal'):
        response = client.post(base + suffix, headers=headers, json={})
        assert response.status_code == 403, (suffix, response.text)
    # The Deep Agents runtime reads goal state every turn; that is not steering.
    assert client.post(base + '/goal', headers=headers, json={'action': 'get'}).status_code == 200
    response = client.get(base + '/github.git/info/refs?service=git-upload-pack', headers=headers)
    assert response.status_code == 403, response.text


def connection_role_run(users_app, monkeypatch):
    from test_spend import active
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    run = active(app, 'google:maya')
    app.state.store.execute('UPDATE runs SET plugins=? WHERE id=?',
                            ('["github","notion","linear","slack"]', run['id']))
    run = app.state.store.run(run['id'])
    sign_as(app, client, 'tin@berri.ai')
    role = create_role(client, 'app-user', ['sessions.create', 'connections.read', 'connections.write'])
    assert assign(client, role_id='app-user').status_code == 200
    monkeypatch.setattr(app.state.connectors, 'allowed', lambda *a, **kw: True)

    def revoke_write():
        app.state.user_roles.enterprise.save(RoleDefinition(
            id=role['id'], name=role['name'], description=role['description'],
            permissions=['sessions.create', 'connections.read'], revision=role['revision']),
            {'method': 'google', 'identity': {'email': 'tin@berri.ai'}}, role['id'])

    return app, client, run, revoke_write


def test_custom_app_reader_cannot_invoke_external_write_tools(users_app, monkeypatch):
    app, client, run, revoke = connection_role_run(users_app, monkeypatch)
    revoke()
    headers = {'Authorization': 'Bearer capability'}
    route = f"/broker/{run['id']}/tools"
    catalog = client.get(route, headers=headers)
    assert catalog.status_code == 200, catalog.text
    names = {tool['name'] for tool in catalog.json()}
    assert {'notion_search', 'linear_search', 'github_repository', 'slack_search'} <= names
    writes = {'notion_append', 'linear_comment', 'github_create_issue', 'slack_send'}
    assert not names & writes
    for name in writes:
        response = client.post(route + '/call', headers=headers, json={'name': name, 'arguments': {}})
        assert response.status_code == 403, (name, response.text)


async def test_connector_write_revoked_while_waiting_for_credentials(users_app, monkeypatch):
    import asyncio
    from app.connector_errors import ConnectorError
    app, _, run, revoke = connection_role_run(users_app, monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def credentials(provider):
        entered.set()
        await release.wait()
        return {'access_token': 'test-only-provider-token'}

    async def request(*args, **kwargs):
        calls.append((args, kwargs))
        return {'results': []}

    monkeypatch.setattr(app.state.connectors, 'credentials', credentials)
    monkeypatch.setattr(app.state.connectors, 'request', request)
    task = asyncio.create_task(app.state.connectors.call('notion_append',
        {'page_id': 'a' * 32, 'text': 'Authorized before waiting.'}, run=run))
    await asyncio.wait_for(entered.wait(), 3)
    revoke()
    release.set()
    with pytest.raises(ConnectorError) as error:
        await task
    assert error.value.code == 'access_denied' and error.value.dispatched is False
    assert calls == []


async def test_role_revocation_between_notion_parts_preserves_acknowledged_writes(users_app, monkeypatch):
    app, _, run, revoke = connection_role_run(users_app, monkeypatch)
    calls = []

    async def credentials(provider):
        return {'access_token': 'test-only-provider-token'}

    async def request(*args, **kwargs):
        calls.append((args, kwargs))
        revoke()
        return {'results': [{'id': 'saved-first-part'}]}

    monkeypatch.setattr(app.state.connectors, 'credentials', credentials)
    monkeypatch.setattr(app.state.connectors, 'request', request)
    result = await app.state.connectors.call('notion_append',
        {'page_id': 'a' * 32, 'text': 'x' * 210000}, run=run)
    assert len(calls) == 1
    assert result['acknowledged_results'] == [{'id': 'saved-first-part'}]
    assert result['completed_characters'] == 200000
    assert result['dispatched'] is True and result['outcome'] == 'failed'
    assert result['outcome_uncertain'] is False


async def test_github_revocation_after_blob_preserves_uncertain_publication(users_app, monkeypatch):
    from app.connector_errors import ConnectorError
    from app.github import Publish
    from test_github import GitHubAPI, PAYLOAD, select
    app, _, run, revoke = connection_role_run(users_app, monkeypatch)
    github = app.state.connectors.github
    select(app)
    api = GitHubAPI(github, monkeypatch)

    def on_call(method, path):
        if method == 'POST' and path.endswith('/git/blobs'):
            revoke()

    api.on_call = on_call
    with pytest.raises(ConnectorError) as error:
        await github.create_change_commit(run, Publish.model_validate(PAYLOAD), 'test-only-token',
                                         api.repository_id, github.connection_version(), 'github_create_pull_request')
    assert [path for method, path, _ in api.calls if method == 'POST'] == [
        f'/repositories/{api.repository_id}/git/blobs']
    receipt = error.value.receipt(write=True)
    assert receipt['code'] == 'access_denied' and receipt['dispatched'] is None
    assert receipt['outcome'] == 'unknown' and receipt['outcome_uncertain']


def test_explicit_organizations_isolate_every_signing_context_with_shared_raw_keys(tmp_path):
    from cryptography.fernet import Fernet
    from itsdangerous import BadSignature
    from app.config import Settings
    from app.governance_audit import GovernanceAudit
    from app.security import Security
    key = Fernet.generate_key().decode()
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://127.0.0.1:8787',
        session_secret='test-only-raw-session-secret', encryption_key=key)
    legacy = Security(settings.model_copy(update={'moyai_organization_id': ''}))
    first = Security(settings.model_copy(update={'moyai_organization_id': 'first-org'}))
    second = Security(settings.model_copy(update={'moyai_organization_id': 'second-org'}))
    assert legacy.secret == settings.session_secret
    assert first.secret != second.secret != legacy.secret
    cookie = first.signer.dumps({'sid': 'shared-sid', 'role': 'admin', 'method': 'local'})
    assert first.signer.loads(cookie)['sid'] == 'shared-sid'
    for verifier in (legacy, second):
        with pytest.raises(BadSignature):
            verifier.signer.loads(cookie)
    assert first.csrf('shared-sid') != second.csrf('shared-sid')
    # Explicit signer salts must also use the organization-scoped key.
    token = first.signer.dumps({'state': 'oauth-test'}, salt='oauth-state-v1')
    with pytest.raises(BadSignature):
        second.signer.loads(token, salt='oauth-state-v1')
    cursor = GovernanceAudit.__new__(GovernanceAudit)
    cursor.security = first
    signed = cursor.cursor(10, 9)
    cursor.security = second
    with pytest.raises(HTTPException) as error:
        cursor.read_cursor(signed)
    assert error.value.status_code == 422
