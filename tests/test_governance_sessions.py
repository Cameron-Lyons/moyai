"""Session access follows live governance state, including open streams and retries."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from test_attachments import upload
from test_enterprise_roles import assign, create_role
from test_scim import patch, user
from test_user_roles import sign_as, users_app
from test_workspace import workspace


def event_stream(app, client, run_id):
    """Open the real SSE endpoint with the current cookie, independent of later sign-ins."""
    endpoint = next(route.endpoint for route in app.routes if getattr(route, 'path', '') == '/api/runs/{run_id}/events')
    cookie = ('workspace_session=' + client.cookies['workspace_session']).encode()

    async def receive():
        await asyncio.Event().wait()

    request = Request({'type': 'http', 'method': 'GET', 'path': f'/api/runs/{run_id}/events', 'query_string': b'',
                       'path_params': {'run_id': run_id}, 'headers': [(b'cookie', cookie)]}, receive)
    return endpoint, request


async def next_status(stream):
    while not (record := await anext(stream)).startswith('event: run-status'):
        pass
    return record


@pytest.mark.parametrize('revocation', ['scim', 'role'])
async def test_open_event_stream_ends_when_access_is_revoked(users_app, revocation):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    issued = client.post('/api/admin/scim/tokens', json={'label': 'Identity provider'})
    client.headers['Authorization'] = 'Bearer ' + issued.json()['token']
    target = user(client, 'maya@berri.ai')
    run = app.state.store.create_run('Watch this session', '', 'demo', [], chat_enabled=True)
    app.state.store.update_run(run['id'], status='idle')
    sign_as(app, client, 'maya@berri.ai')
    endpoint, request = event_stream(app, client, run['id'])
    app.state.event_reauthorize_seconds = 0
    stream = (await endpoint(run['id'], request, 0)).body_iterator
    try:
        # Every poll rechecks here; an active viewer keeps receiving status.
        await next_status(stream)
        await next_status(stream)
        if revocation == 'scim':
            assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 200
        else:
            sign_as(app, client, 'tin@berri.ai')
            create_role(client, 'settings-only', ['workspace.read'])
            assert assign(client, role_id='settings-only').status_code == 200
        assert await anext(stream) == 'event: unauthorized\ndata: {}\n\n'
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
    finally:
        await stream.aclose()


async def test_open_event_stream_does_not_reauthorize_every_poll(users_app, monkeypatch):
    app, client = users_app
    run = app.state.store.create_run('Watch this session', '', 'demo', [], chat_enabled=True)
    app.state.store.update_run(run['id'], status='idle')
    sign_as(app, client, 'maya@berri.ai')
    endpoint, request = event_stream(app, client, run['id'])
    security, checks = app.state.security, []
    original = security.require
    monkeypatch.setattr(security, 'require', lambda *args, **kwargs: checks.append(1) or original(*args, **kwargs))
    stream = (await endpoint(run['id'], request, 0)).body_iterator
    try:
        for _ in range(3):
            await next_status(stream)
        assert app.state.event_reauthorize_seconds == 10 and len(checks) == 1
    finally:
        await stream.aclose()


def test_runtime_manage_reads_analytics_but_cannot_change_the_sandbox_provider(users_app, monkeypatch):
    app, client = users_app
    check = AsyncMock(return_value='Connected')
    monkeypatch.setattr('app.sandbox_settings.provider', lambda candidate, **kwargs: SimpleNamespace(check=check))
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'performance-viewer', ['workspace.read', 'runtime.manage'])
    assert assign(client, role_id='performance-viewer').status_code == 200
    admin_view = client.get('/api/settings/sandboxes').json()
    assert admin_view['public_key'] and 'values' in admin_view['providers']['modal']
    assert 'deployment' in client.get('/api/organization').json()
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/admin/performance').status_code == 200
    assert 'deployment' in client.get('/api/organization').json()
    viewer = client.get('/api/settings/sandboxes')
    assert viewer.status_code == 200 and 'values' not in viewer.json()['providers']['modal'] and 'public_key' not in viewer.json()
    attack = {'provider': 'modal', 'revision': viewer.json()['revision'],
              'values': {'modal_token_id': 'ak-attacker', 'modal_token_secret': 'as-attacker'}}
    assert client.put('/api/settings/sandboxes', json=attack).status_code == 403
    assert app.state.settings.modal_token_id != 'ak-attacker' and not check.called
    sign_as(app, client, 'tin@berri.ai')
    saved = client.put('/api/settings/sandboxes', json={**attack, 'values': {'modal_token_id': 'ak-admin', 'modal_token_secret': 'as-admin'}})
    assert saved.status_code == 200, saved.text
    assert app.state.settings.modal_token_id == 'ak-admin' and saved.json()['providers']['modal']['secrets']['modal_token_id']


def test_organization_deployment_details_are_limited_to_operators(users_app):
    app, client = users_app
    sign_as(app, client, 'maya@berri.ai')
    organization = client.get('/api/organization').json()
    assert organization['role'] == 'member' and organization['id'] == '' and 'deployment' not in organization
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'organization-editor', ['workspace.read', 'organization.manage'])
    assert assign(client, role_id='organization-editor').status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    assert 'namespaces' in client.get('/api/organization').json()['deployment']


def test_session_creators_and_stewards_can_upload_attachments(users_app, monkeypatch):
    app, client = users_app
    monkeypatch.setattr(app.state.manager, 'submit', lambda run: None)
    sign_as(app, client, 'tin@berri.ai')
    create_role(client, 'starter', ['workspace.read', 'sessions.read', 'sessions.create', 'spend.personal'])
    create_role(client, 'steward', ['workspace.read', 'sessions.read', 'sessions.manage'])
    create_role(client, 'reader')
    for email, role in [('maya@berri.ai', 'starter'), ('ana@berri.ai', 'steward'), ('ben@berri.ai', 'reader')]:
        assert assign(client, email, role).status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    file = upload(client)
    assert file.status_code == 200, file.text
    assert client.get(file.json()['url']).status_code == 200
    discarded = upload(client, data=b'Not needed').json()
    assert client.delete('/api/attachments/' + discarded['id']).status_code == 200
    started = client.post('/api/runs', json={'prompt': 'Read the attachment', 'attachment_ids': [file.json()['id']],
                                             'client_id': 'starter-attachment'})
    assert started.status_code == 201, started.text
    sign_as(app, client, 'ana@berri.ai')
    assert upload(client).status_code == 200
    sign_as(app, client, 'ben@berri.ai')
    assert upload(client).status_code == 403
    assert client.delete('/api/attachments/' + discarded['id']).status_code == 403


def test_client_id_retry_returns_the_admitted_session_after_policy_changes(workspace, monkeypatch):
    app, client = workspace
    monkeypatch.setattr(app.state.manager, 'submit', lambda run: None)
    profiles = app.state.security_profiles
    for identity, name, policy in [('a' * 32, 'Linear only', {'connected_apps': ['linear']}),
                                   ('b' * 32, 'Selected', {}), ('c' * 32, 'Other', {})]:
        profiles.save(identity, {'name': name, 'policy': policy}, 'admin')
    implicit = {'prompt': 'Start once', 'plugins': ['github'], 'client_id': 'client-retry-0001'}
    explicit = {**implicit, 'client_id': 'client-retry-0002', 'security_profile_id': 'b' * 32}
    first, chosen = client.post('/api/runs', json=implicit), client.post('/api/runs', json=explicit)
    assert first.status_code == chosen.status_code == 201, (first.text, chosen.text)
    # New defaults/floor, and the previously selected profile is disabled.
    profiles.save_defaults({'default_profile_id': 'a' * 32, 'floor_profile_id': 'a' * 32})
    profiles.save('b' * 32, {'name': 'Selected', 'revision': 1, 'enabled': False}, 'admin')
    for body, original in [(implicit, first), (explicit, chosen)]:
        retry = client.post('/api/runs', json=body)
        assert retry.status_code == 201, retry.text
        assert retry.json()['id'] == original.json()['id']
    assert len(app.state.store.rows('SELECT id FROM runs')) == 2
    conflict = client.post('/api/runs', json={**implicit, 'security_profile_id': 'c' * 32})
    assert conflict.status_code == 409 and 'security profile' in conflict.json()['detail']
    # New submissions are still admitted under the current policy.
    assert client.post('/api/runs', json={**implicit, 'client_id': 'client-retry-0003'}).status_code == 422
    # A snapshot whose session disappears before admission never starts another session.
    store = app.state.store
    snapshot = store.rows('SELECT security_profile_id,security_profile_revision,security_policy FROM runs WHERE id=?',
                          (first.json()['id'],))[0]
    monkeypatch.setattr(store, 'admitted_security', lambda client_id, user_id: snapshot)
    vanished = client.post('/api/runs', json={**implicit, 'client_id': 'client-retry-0004'})
    assert vanished.status_code == 409 and 'deleted' in vanished.json()['detail']
    assert len(store.rows('SELECT id FROM runs')) == 2
