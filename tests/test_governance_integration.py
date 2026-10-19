"""Governance across real public and capability-authenticated broker routes."""
import json
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import Settings
from app.main import create_app
from app.security import digest
from test_user_roles import sign_as, users_app


@pytest.fixture
def governed_app(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://127.0.0.1:8787',
                        google_allowed_domains='example.com', agent_harness='hermes',
                        litellm_api_key='', modal_token_id='', modal_token_secret='',
                        repository_context_enabled=False, bundled_skills_enabled=False)
    app = create_app(settings)
    monkeypatch.setattr(app.state.manager, 'submit', Mock())
    monkeypatch.setattr(app.state.session_titles, 'request', AsyncMock())
    with TestClient(app, base_url=settings.public_url, client=('127.0.0.1', 54000)) as client:
        session = client.get('/api/session').json()
        client.headers.update({'Origin': settings.public_url, 'X-CSRF-Token': session['csrf']})
        yield app, client


def save_profile(client, name='Restricted operations', **policy):
    response = client.post('/api/admin/security-profiles', json={'name': name, 'policy': policy})
    assert response.status_code == 201, response.text
    return response.json()


def create_session(client, **fields):
    response = client.post('/api/runs', json={'prompt': 'Inspect the release workflow', 'mode': 'demo', **fields})
    assert response.status_code == 201, response.text
    return response.json()


def activate(app, identity, *, plugins=(), actor=None):
    store = app.state.store
    store.claim_message(identity)
    store.execute('UPDATE runs SET mode=?,plugins=? WHERE id=?', ('modal', json.dumps(list(plugins)), identity))
    if actor:
        store.execute('UPDATE runs SET owner_id=?,active_user_id=? WHERE id=?', (actor, actor, identity))
    store.update_run(identity, status='running', token_hash=digest('test-run-capability'))
    return {'Authorization': 'Bearer test-run-capability'}


def test_profile_catalog_requires_live_security_management_permission(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    profile = save_profile(client)
    role = client.post('/api/admin/roles', json={
        'id': 'profile-reader', 'name': 'Profile reader', 'permissions': ['workspace.read']}).json()
    assignment = client.put('/api/admin/role-assignments', json={
        'email': 'maya@berri.ai', 'role_id': role['id'], 'revision': 0})
    assert assignment.status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    cookie = dict(client.cookies)
    assert client.get('/api/security-profiles').status_code == 403
    sign_as(app, client, 'tin@berri.ai')
    update = client.put('/api/admin/roles/' + role['id'], json={
        'id': role['id'], 'name': role['name'], 'permissions': ['security.manage'], 'revision': role['revision']})
    assert update.status_code == 200
    client.cookies.clear()
    client.cookies.update(cookie)
    catalog = client.get('/api/security-profiles')
    assert catalog.status_code == 200
    assert profile['id'] in {item['id'] for item in catalog.json()}


@pytest.mark.parametrize('disabled', [False, True])
def test_workflow_rejects_new_missing_or_disabled_policy_binding(governed_app, disabled):
    app, client = governed_app
    identity = 'a' * 32
    if disabled:
        identity = save_profile(client)['id']
        assert client.delete('/api/admin/security-profiles/' + identity).status_code == 200
    response = client.post('/api/automations', json={'definition': {
        'name': 'Invalid policy binding', 'prompt': 'Inspect the release',
        'mode': 'demo', 'security_profile_id': identity}})
    assert response.status_code == (409 if disabled else 404), response.text
    assert app.state.store.rows('SELECT id FROM automations') == []


def test_profile_default_session_revision_and_replay_stay_pinned(governed_app):
    app, client = governed_app
    profile = save_profile(client, connected_apps=[], git_access='read')
    defaults = client.put('/api/admin/security-profiles/defaults', json={'default_profile_id': profile['id']})
    assert defaults.status_code == 200
    run = create_session(client, client_id='governance-session-one')
    saved = app.state.store.run(run['id'])
    assert saved['owner_id'] == saved['active_user_id'] == 'shared:local:admin'
    assert saved['security_profile_id'] == profile['id'] and saved['security_profile_revision'] == 1
    update = client.put('/api/admin/security-profiles/' + profile['id'], json={
        'name': profile['name'], 'revision': 1, 'policy': {'connected_apps': ['github'], 'git_access': 'write'}})
    assert update.status_code == 200
    again = create_session(client, client_id='governance-session-one')
    assert again['id'] == run['id']
    assert app.state.store.run(run['id'])['security_profile_revision'] == 1
    assert app.state.security_profiles.effective(saved)['git_access'] == 'read'
    other = save_profile(client, name='Another profile')
    response = client.post('/api/runs', json={'prompt': 'Inspect the release workflow', 'mode': 'demo',
        'client_id': 'governance-session-one', 'security_profile_id': other['id']})
    assert response.status_code == 409


@pytest.mark.parametrize('change', ['default', 'revision', 'disabled', 'apps', 'repository', 'provider'])
def test_session_policy_is_resolved_again_at_commit(governed_app, monkeypatch, change):
    app, client = governed_app
    profile = save_profile(client, name='Initial policy')
    assert client.put('/api/admin/security-profiles/defaults', json={
        'default_profile_id': profile['id']}).status_code == 200
    fields = {} if change == 'default' else {'security_profile_id': profile['id']}
    if change == 'apps':
        fields['plugins'] = ['github']
    if change == 'repository':
        fields['repo_url'] = 'https://github.com/example/project'
    original = app.state.store.create_run

    def changed_create(*args, **kwargs):
        profiles = app.state.security_profiles
        if change == 'default':
            other = profiles.save('b' * 32, {'name': 'New default', 'policy': {'git_access': 'none'}}, 'admin')
            profiles.save_defaults({'revision': 1, 'default_profile_id': other['id']})
        elif change == 'disabled':
            profiles.save_defaults({'revision': 1})
            profiles.delete(profile['id'])
        else:
            policy = {'connected_apps': []} if change == 'apps' else (
                {'network_domains': []} if change == 'provider' else {'git_access': 'none'})
            profiles.save(profile['id'], {'name': profile['name'], 'revision': 1, 'policy': policy}, 'admin')
        return original(*args, **kwargs)

    monkeypatch.setattr(app.state.store, 'create_run', changed_create)
    response = client.post('/api/runs', json={'prompt': 'Admit under the current policy', 'mode': 'demo', **fields})
    expected = 201 if change in {'default', 'revision'} else 422 if change in {'apps', 'repository'} else 409
    assert response.status_code == expected, response.text
    if expected == 201:
        saved = app.state.store.run(response.json()['id'])
        assert json.loads(saved['security_policy'])['git_access'] == 'none'
        assert saved['security_profile_id'] == ('b' * 32 if change == 'default' else profile['id'])
        assert saved['security_profile_revision'] == (1 if change == 'default' else 2)
    else:
        assert app.state.store.rows('SELECT id FROM runs') == []
        app.state.manager.submit.assert_not_called()


def test_network_provider_rejection_happens_before_repository_or_launch(governed_app, monkeypatch):
    app, client = governed_app
    profile = save_profile(client, network_domains=['approved.example.com'])
    github = AsyncMock()
    monkeypatch.setattr(app.state.connectors.github, 'public_repository', github)
    response = client.post('/api/runs', json={'prompt': 'Inspect the repository', 'mode': 'modal',
        'repo_url': 'https://github.com/example/project', 'security_profile_id': profile['id']})
    assert response.status_code == 409 and 'Substrate' in response.json()['detail']
    github.assert_not_called()
    app.state.manager.submit.assert_not_called()
    assert not app.state.store.rows('SELECT 1 FROM runs')


def test_disallowed_creation_inputs_are_rejected_before_connector_lookup(governed_app, monkeypatch):
    app, client = governed_app
    profile = save_profile(client, connected_apps=[], git_access='none')
    lookup = AsyncMock()
    monkeypatch.setattr(app.state.connectors.github, 'selected_target', lookup)
    app_result = client.post('/api/runs', json={'prompt': 'Inspect releases', 'mode': 'demo',
        'plugins': ['linear'], 'security_profile_id': profile['id']})
    assert app_result.status_code == 422
    repo_result = client.post('/api/runs', json={'prompt': 'Inspect releases', 'mode': 'demo',
        'repo_url': 'https://github.com/example/project', 'security_profile_id': profile['id']})
    assert repo_result.status_code == 422
    lookup.assert_not_called()
    app.state.manager.submit.assert_not_called()


def test_side_chat_selection_cannot_broaden_parent_policy(governed_app):
    app, client = governed_app
    restricted = save_profile(client, connected_apps=[], git_access='none')
    broad = save_profile(client, name='Broad profile')
    parent = create_session(client, security_profile_id=restricted['id'])
    child = create_session(client, side_chat_of=parent['id'], security_profile_id=broad['id'])
    policy = app.state.security_profiles.effective(app.state.store.run(child['id']))
    assert policy['git_access'] == 'none' and policy['connected_apps'] == []


def test_disallowed_broker_app_never_reaches_connector(governed_app, monkeypatch):
    app, client = governed_app
    profile = save_profile(client, connected_apps=[])
    run = create_session(client, security_profile_id=profile['id'])
    app.state.connectors.save('linear', {'access_token': 'test-token', 'kind': 'personal'}, 'Test connection')
    headers = activate(app, run['id'], plugins=['linear'])
    dispatch = AsyncMock()
    monkeypatch.setattr(app.state.connectors, 'call', dispatch)
    catalog = client.get('/broker/' + run['id'] + '/tools', headers=headers)
    assert catalog.status_code == 200 and not any(tool['name'] == 'linear_search' for tool in catalog.json())
    result = client.post('/broker/' + run['id'] + '/tools/call', headers=headers,
                         json={'name': 'linear_search', 'arguments': {'query': 'ticket'}})
    assert result.status_code == 403
    dispatch.assert_not_called()
    assert not app.state.store.rows("SELECT 1 FROM events WHERE run_id=? AND kind='tool_dispatch'", (run['id'],))


def test_raw_credential_materialize_cannot_bypass_disabled_tool(governed_app, monkeypatch):
    app, client = governed_app
    profile = save_profile(client, tools=[])
    run = create_session(client, security_profile_id=profile['id'])
    headers = activate(app, run['id'])
    app.state.settings.temporal_enabled = True  # Expose credential transport, without starting a worker.
    authorization = Mock(side_effect=AssertionError('A denied tool reached credential authorization'))
    monkeypatch.setattr(app.state.credentials, 'authorized_request', authorization)
    result = client.post('/broker/' + run['id'] + '/credentials/materialize', headers=headers,
                         json={'request_ids': ['a' * 32]})
    assert result.status_code == 403
    authorization.assert_not_called()
    app.state.settings.temporal_enabled = False


def test_raw_artifact_transfer_cannot_bypass_disabled_publish(governed_app):
    app, client = governed_app
    profile = save_profile(client, tools=[])
    run = create_session(client, security_profile_id=profile['id'])
    headers = activate(app, run['id'])
    response = client.post('/broker/' + run['id'] + '/artifacts/transfer', headers=headers,
                           json={'action': 'begin', 'upload_id': 'b' * 32, 'path': 'deliverable.txt', 'size': 0, 'sha256': 'e' * 64})
    assert response.status_code == 403
    assert not app.state.store.rows('SELECT 1 FROM artifact_uploads WHERE run_id=?', (run['id'],))


def test_automation_pins_policy_before_wake_and_retains_occurrence(governed_app):
    app, client = governed_app
    profile = save_profile(client, connected_apps=[], git_access='read')
    response = client.post('/api/automations', json={'definition': {'name': 'Inspect releases',
        'prompt': 'Inspect release status', 'mode': 'demo', 'security_profile_id': profile['id']}})
    assert response.status_code == 201, response.text
    automation = response.json()
    assert app.state.store.rows('SELECT security_profile_id FROM automations WHERE id=?', (automation['id'],))[0]['security_profile_id'] == profile['id']
    path = '/api/automations/' + automation['id'] + '/run'
    first = client.post(path, json={'revision': 1, 'client_id': 'governance-occurrence'})
    assert first.status_code == 202 and first.json()['outcome'] == 'started', first.text
    run = app.state.store.run(first.json()['run_id'])
    assert run['owner_id'] == run['active_user_id'] == 'shared:local:admin'
    assert run['security_profile_id'] == profile['id'] and run['security_profile_revision'] == 1
    assert json.loads(run['security_policy'])['git_access'] == 'read'
    submitted = app.state.manager.submit.call_args.args[0]
    assert submitted['security_profile_revision'] == 1
    client.put('/api/admin/security-profiles/' + profile['id'], json={'name': profile['name'], 'revision': 1, 'policy': {}})
    again = client.post(path, json={'revision': 1, 'client_id': 'governance-occurrence'})
    assert again.json() == first.json()
    assert app.state.store.run(run['id'])['security_profile_revision'] == 1


def test_disabled_automation_policy_blocks_before_repository_identification(governed_app, monkeypatch):
    app, client = governed_app
    profile = save_profile(client)
    response = client.post('/api/automations', json={'definition': {'name': 'Inspect releases',
        'prompt': 'Inspect release status', 'mode': 'demo', 'security_profile_id': profile['id']}})
    assert response.status_code == 201, response.text
    automation = response.json()
    assert client.delete('/api/admin/security-profiles/' + profile['id']).status_code == 200
    identify = AsyncMock()
    monkeypatch.setattr(app.state.automations, 'identify_repositories', identify)
    result = client.post('/api/automations/' + automation['id'] + '/run',
                         json={'revision': 1, 'client_id': 'disabled-governance-policy'})
    assert result.status_code == 202 and result.json()['outcome'] == 'blocked', result.text
    identify.assert_not_called()
    app.state.manager.submit.assert_not_called()
    assert not app.state.store.rows('SELECT 1 FROM runs')


def test_prepared_pool_cannot_hand_out_unrestricted_machine(governed_app):
    from app.prepared_sandboxes import PreparedSandboxes
    app, client = governed_app
    run = create_session(client)
    # A policy-bound restored/legacy row must fail pool admission even if its
    # provider field still says Modal; ordinary provisioning rejects it too.
    app.state.store.execute('UPDATE runs SET mode=?,security_policy=? WHERE id=?',
                           ('modal', json.dumps({'network_domains': []}), run['id']))
    app.state.settings.sandbox_prepared_pool_size = 1
    pool = PreparedSandboxes(app.state.manager)
    current = app.state.store.run(run['id'])
    assert not pool.eligible(current)
    assert not pool.assign(run['id'], current, {})


def test_deactivation_blocks_new_tools_but_keeps_admitted_receipts(governed_app):
    app, client = governed_app
    run = create_session(client)
    actor = app.state.store.identity({'method': 'google', 'identity': {
        'sub': 'verified-worker', 'email': 'worker@example.com', 'domain': 'example.com', 'name': 'Worker'}})
    headers = activate(app, run['id'], actor=actor)
    assert client.get('/broker/' + run['id'] + '/tools', headers=headers).status_code == 200
    initialized = client.post('/broker/' + run['id'] + '/context/journal', headers=headers,
                              json={'action': 'import', 'manifest': {'id': 'empty', 'count': 0}, 'entries': [], 'complete': True})
    assert initialized.status_code == 200, initialized.text
    with app.state.store.connect() as conn:
        conn.begin_write()
        app.state.scim.write_in(conn, 'User', {'userName': 'worker@example.com', 'active': False})
    assert client.get('/broker/' + run['id'] + '/tools', headers=headers).status_code == 403
    receipt = {'action': 'append', 'entries': [{'id': 'admitted-receipt', 'message': {
        'role': 'assistant', 'content': 'Already completed result'}}]}
    response = client.post('/broker/' + run['id'] + '/context/journal', headers=headers, json=receipt)
    assert response.status_code == 200, response.text
    invalid = client.post('/broker/' + run['id'] + '/context/journal',
                          headers={'Authorization': 'Bearer different-capability'}, json=receipt)
    assert invalid.status_code == 401


def test_deactivation_during_tool_upload_blocks_dispatch(governed_app, monkeypatch):
    app, client = governed_app
    run = create_session(client)
    actor = app.state.store.identity({'method': 'google', 'identity': {
        'sub': 'upload-worker', 'email': 'upload-worker@example.com', 'domain': 'example.com'}})
    headers = activate(app, run['id'], actor=actor, plugins=['linear'])
    app.state.connectors.save('linear', {'access_token': 'fixture-token', 'kind': 'personal'}, 'Test team')
    assert 'linear_search' in {tool['name'] for tool in client.get(
        '/broker/' + run['id'] + '/tools', headers=headers).json()}
    original = Request.body
    dispatched = AsyncMock(side_effect=AssertionError('Revoked requester reached tool dispatch'))
    monkeypatch.setattr(app.state.connectors, 'call', dispatched)

    async def revoked_body(request):
        body = await original(request)
        if request.url.path == '/broker/' + run['id'] + '/tools/call':
            with app.state.store.connect() as conn:
                conn.begin_write()
                app.state.scim.write_in(conn, 'User', {
                    'userName': 'upload-worker@example.com', 'active': False})
        return body

    monkeypatch.setattr(Request, 'body', revoked_body)
    response = client.post('/broker/' + run['id'] + '/tools/call', headers=headers,
                           json={'name': 'linear_search', 'arguments': {'query': 'Release'}})
    assert response.status_code == 403, response.text
    dispatched.assert_not_called()


def test_session_creation_rechecks_revocation_inside_commit(governed_app, monkeypatch):
    app, client = governed_app
    from test_user_roles import sign_as
    app.state.settings.google_client_id = 'fixture-client'
    app.state.settings.google_client_secret = 'fixture-secret'
    app.state.settings.google_admin_emails = 'admin@example.com'
    sign_as(app, client, 'worker@example.com')
    original = app.state.store.create_run

    def revoked_create(*args, **kwargs):
        with app.state.store.connect() as conn:
            conn.begin_write()
            app.state.scim.write_in(conn, 'User', {'userName': 'worker@example.com', 'active': False})
        return original(*args, **kwargs)

    monkeypatch.setattr(app.state.store, 'create_run', revoked_create)
    response = client.post('/api/runs', json={'prompt': 'Inspect the release workflow', 'mode': 'demo'})
    assert response.status_code == 403, response.text
    assert not app.state.store.rows('SELECT 1 FROM runs')
    app.state.manager.submit.assert_not_called()


def test_goal_runtime_channel_survives_tool_allowlist_but_user_control_does_not(governed_app):
    app, client = governed_app
    # A tools allowlist without 'goal' must not break the runtime's per-turn goal reads.
    profile = save_profile(client, tools=['github_search'])
    run = create_session(client, security_profile_id=profile['id'])
    headers = activate(app, run['id'])
    path = '/broker/' + run['id'] + '/goal'
    assert client.post(path, headers=headers, json={'action': 'get'}).json()['goal'] is None
    assert client.post(path, headers=headers, json={'action': 'tick', 'segment': 's', 'elapsed': 1}).status_code == 200
    control = client.post(path, headers=headers, json={'action': 'control'})
    assert control.status_code == 403 and 'security profile' in control.json()['detail']


def test_agent_created_automation_cannot_broaden_session_policy(governed_app):
    from app.automations import Definition
    app, client = governed_app
    strict = save_profile(client, 'Read only', git_access='read', connected_apps=[])
    broader = save_profile(client, 'Broader', git_access='read')
    run = app.state.store.run(create_session(client, security_profile_id=strict['id'])['id'])
    tools = app.state.automation_tools
    definition = {'name': 'Nightly', 'prompt': 'Summarize releases', 'mode': 'demo'}
    for selected in ('', broader['id']):
        with pytest.raises(Exception) as error:
            tools.check_policy(run, Definition.model_validate({**definition, 'security_profile_id': selected}))
        assert getattr(error.value, 'status_code', None) == 403
    tools.check_policy(run, Definition.model_validate({**definition, 'security_profile_id': strict['id']}))


def test_repository_context_follows_session_git_policy(governed_app):
    app, client = governed_app
    context = app.state.repository_context
    allowed = app.state.store.run(create_session(client)['id'])
    denied = app.state.store.run(create_session(client, security_profile_id=save_profile(client, git_access='none')['id'])['id'])
    assert context.permitted(allowed)
    assert not context.permitted(denied)


def test_tool_listing_resolves_session_policy_once(governed_app, monkeypatch):
    from app.security_profiles import SecurityProfiles
    app, client = governed_app
    profile = save_profile(client, git_access='read')
    run = create_session(client, security_profile_id=profile['id'])
    for provider in ('github', 'linear'):
        app.state.connectors.save(provider, {'access_token': 'test-token', 'kind': 'personal'}, 'Test connection')
    headers = activate(app, run['id'], plugins=['github', 'linear'])
    calls, original = [], SecurityProfiles.effective
    monkeypatch.setattr(SecurityProfiles, 'effective', lambda self, *args, **kwargs: calls.append(1) or original(self, *args, **kwargs))
    catalog = client.get('/broker/' + run['id'] + '/tools', headers=headers)
    assert catalog.status_code == 200 and any(tool['name'].startswith('linear_') for tool in catalog.json())
    # Once for the catalog filter; never once per listed tool.
    assert len(calls) <= 2, len(calls)


def test_tool_claim_reads_policy_without_a_nested_connection(governed_app, monkeypatch):
    from types import SimpleNamespace
    from app.tool_dispatch import ToolDispatch
    app, client = governed_app
    run = create_session(client, security_profile_id=save_profile(client, git_access='read')['id'])
    activate(app, run['id'])
    caller, store = app.state.store.run(run['id']), app.state.store
    import threading
    from contextlib import contextmanager
    claimant, depth, deepest, original = threading.get_ident(), [0], [0], type(store).connect
    @contextmanager
    def tracked(self, *args, **kwargs):
        mine = threading.get_ident() == claimant  # Ignore background pollers.
        depth[0] += mine
        deepest[0] = max(deepest[0], depth[0])
        try:
            with original(self, *args, **kwargs) as conn:
                yield conn
        finally:
            depth[0] -= mine
    monkeypatch.setattr(type(store), 'connect', tracked)
    body = SimpleNamespace(request_id='nested-check', input_id=caller['active_message_id'], name='sessions_search', arguments={})
    assert ToolDispatch(store, caller, body).claim() is None
    assert deepest[0] == 1
