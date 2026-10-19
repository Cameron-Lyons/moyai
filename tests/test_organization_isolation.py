"""Two dedicated deployments exercise independent authorization and resources."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

pytest.importorskip("app.main", reason="Legacy governance integration contracts require the retired runtime; native enforcement is separate work.")

from app.blob_storage import ObjectStorage
from app.config import Settings
from app.database import DatabaseError
from app.db import Store
from app.durable_runner import DurableRunner
from app.main import create_app
from app.organization_scope import OrganizationScope, NAMESPACE_FIELDS, scoped_name
from app.security import digest


def configured(path, identity, **fields):
    return Settings(_env_file=None, data_dir=path, moyai_organization_id=identity,
        public_url='https://' + identity + '.example.com', organization_name=identity.title(),
        workspace_password=identity + '-test-password',
        session_secret=identity + '-test-session-key', encryption_key=Fernet.generate_key().decode(),
        google_allowed_domains='example.com', bundled_skills_enabled=False,
        repository_context_enabled=False, litellm_api_key='', modal_token_id='', modal_token_secret='',
        agent_harness='hermes', **fields)


@pytest.fixture
def deployments(tmp_path, monkeypatch):
    with ExitStack() as stack:
        values = []
        for identity in ('north', 'south'):
            settings = configured(tmp_path / identity, identity)
            app = create_app(settings)
            monkeypatch.setattr(app.state.manager, 'submit', Mock())
            monkeypatch.setattr(app.state.session_titles, 'request', AsyncMock())
            client = stack.enter_context(TestClient(app, base_url=settings.public_url,
                                                    client=('127.0.0.1', 55000)))
            client.headers['Origin'] = settings.public_url
            login = client.post('/api/login', json={'password': settings.workspace_password})
            assert login.status_code == 200, login.text
            session = client.get('/api/session').json()
            client.headers['X-CSRF-Token'] = session['csrf']
            values.append((app, client))
        yield values


def profile(client, name):
    response = client.post('/api/admin/security-profiles', json={'name': name, 'policy': {'connected_apps': []}})
    assert response.status_code == 201, response.text
    return response.json()


def run(client, prompt):
    response = client.post('/api/runs', json={'mode': 'demo', 'prompt': prompt})
    assert response.status_code == 201, response.text
    return response.json()


def capability(app, identity):
    store = app.state.store
    message = store.claim_message(identity)
    token = DurableRunner.token(SimpleNamespace(settings=app.state.settings), identity, message['id'])
    store.execute("UPDATE runs SET mode='modal' WHERE id=?", (identity,))
    store.update_run(identity, status='running', token_hash=digest(token))
    return {'Authorization': 'Bearer ' + token}


WRAPPER = Path(__file__).resolve().parents[1] / 'deploy_modal.py'


def wrapper(monkeypatch, settings, name):
    monkeypatch.setattr('app.config.Settings', lambda: settings)
    spec = importlib.util.spec_from_file_location(name, WRAPPER)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def test_namespace_defaults_are_distinct_idempotent_and_legacy_unchanged(tmp_path):
    # Temporal Cloud namespaces are <name>.<account>; operators provision each one.
    north = configured(tmp_path / 'north', 'north', object_storage_bucket='shared', modal_volume_name='checkpoints',
                       temporal_namespace='north.a1b2c')
    south = configured(tmp_path / 'south', 'south', object_storage_bucket='shared', modal_volume_name='checkpoints',
                       temporal_namespace='south.a1b2c')
    for field in NAMESPACE_FIELDS:
        assert getattr(north, field) != getattr(south, field)
    assert north.temporal_namespace == 'north.a1b2c'
    assert north.temporal_task_queue == 'moyai-sessions-v1-org-north'
    again = Settings(_env_file=None, **north.model_dump())
    assert again.model_dump() == north.model_dump()
    saved_override = Settings(_env_file=None, **{**north.model_dump(), 'modal_app_name': 'saved-app', 'substrate_atespace': 'saved-space'})
    assert saved_override.modal_app_name == 'saved-app-org-north'
    assert saved_override.substrate_atespace == 'saved-space-org-north'
    bounded = configured(tmp_path / 'bounded', 'n' * 32, modal_app_name='a' * 60, substrate_atespace='b' * 60)
    assert len(bounded.modal_app_name) <= 64 and len(bounded.substrate_atespace) <= 63
    legacy = Settings(_env_file=None)
    assert legacy.temporal_namespace == 'default'
    assert legacy.temporal_task_queue == 'moyai-sessions-v1'
    assert legacy.object_storage_prefix == 'moyai'
    assert legacy.modal_app_name == 'hermes-workspace'
    assert legacy.substrate_atespace == 'moyai'


def test_scoped_object_prefix_is_bounded_on_first_construction(tmp_path):
    longest = configured(tmp_path / 'longest', 'acme', object_storage_prefix='p' * 181)
    assert longest.object_storage_prefix == 'p' * 181 + '/organizations/acme'
    # Saved sandbox settings rebuild Settings from model_dump on every later start.
    assert Settings(_env_file=None, **longest.model_dump()).model_dump() == longest.model_dump()
    with pytest.raises(ValidationError, match='too long after organization scoping'):
        configured(tmp_path / 'too-long', 'acme', object_storage_prefix='p' * 182)
    assert Settings(_env_file=None, object_storage_prefix='p' * 200).object_storage_prefix == 'p' * 200


def test_temporal_org_deployment_requires_explicit_namespace(tmp_path):
    path = tmp_path / 'temporal'
    store = Store(path)
    try:
        with pytest.raises(DatabaseError, match='TEMPORAL_NAMESPACE'):
            OrganizationScope(store, configured(path, 'north', temporal_enabled=True))
        with store.connect() as conn:
            assert 'organization_scope' not in conn.table_names()  # Refused before any DDL.
        scope = OrganizationScope(store, configured(path, 'north', temporal_enabled=True, temporal_namespace='north.a1b2c'))
        assert scope.metadata()['deployment_mode'] == 'dedicated'
        assert scope.metadata()['namespaces']['temporal_namespace'] == 'north.a1b2c'
    finally:
        store.close()
    legacy = tmp_path / 'legacy'
    store = Store(legacy)
    try:
        scope = OrganizationScope(store, Settings(_env_file=None, data_dir=legacy, temporal_enabled=True))
        assert scope.metadata()['id'] == '' and scope.metadata()['deployment_mode'] == 'legacy'
    finally:
        store.close()


def test_database_pin_is_immutable_and_missing_id_cannot_open_it(tmp_path):
    path = tmp_path / 'pinned'
    store = Store(path)
    try:
        OrganizationScope(store, configured(path, 'north'))
        OrganizationScope(store, configured(path, 'north'))
        for settings in (configured(path, 'south'), Settings(_env_file=None, data_dir=path)):
            with pytest.raises(DatabaseError, match='different organization'):
                OrganizationScope(store, settings)
        assert store.rows('SELECT organization_id FROM organization_scope')[0]['organization_id'] == 'north'
    finally:
        store.close()


def test_legacy_data_requires_namespace_migration_before_adoption(tmp_path):
    path = tmp_path / 'legacy'
    store = Store(path)
    try:
        OrganizationScope(store, Settings(_env_file=None, data_dir=path))
        original = store.create_run('Existing work', '', 'demo', [])
        with pytest.raises(DatabaseError, match='namespace migration'):
            OrganizationScope(store, configured(path, 'north'))
        assert not store.rows('SELECT 1 FROM organization_scope')
        assert store.run(original['id'])['prompt'] == 'Existing work'
        OrganizationScope(store, Settings(_env_file=None, data_dir=path))
    finally:
        store.close()


def test_foreign_object_reference_cannot_reach_shared_storage(tmp_path):
    north = ObjectStorage(configured(tmp_path / 'north', 'north', object_storage_bucket='shared'))
    south = ObjectStorage(configured(tmp_path / 'south', 'south', object_storage_bucket='shared'))
    checksum = 'a' * 64
    assert north.identity != south.identity and north.key(checksum) != south.key(checksum)
    south.client = Mock(side_effect=AssertionError('Foreign object reference reached shared storage'))
    with pytest.raises(HTTPException):
        south.read('s3:' + north.identity + ':' + checksum, 100)
    south.client.assert_not_called()


def test_apps_pin_database_before_loading_other_org_settings(deployments):
    (north, north_client), (south, south_client) = deployments
    assert north_client.get('/api/organization').json()['id'] == 'north'
    assert south_client.get('/api/organization').json()['id'] == 'south'
    assert north.state.store.rows('SELECT organization_id FROM organization_scope')[0]['organization_id'] == 'north'
    assert south.state.store.rows('SELECT organization_id FROM organization_scope')[0]['organization_id'] == 'south'
    for identity in ('south', ''):
        changed = Settings(_env_file=None, **{**north.state.settings.model_dump(), 'moyai_organization_id': identity})
        with pytest.raises(DatabaseError, match='different organization|owns this Postgres schema'):
            create_app(changed)


def test_reopening_deployment_with_another_org_is_rejected_before_clients(tmp_path):
    settings = configured(tmp_path / 'reopened', 'north')
    original = create_app(settings)
    original.state.store.close()
    for identity in ('south', ''):
        changed = Settings(_env_file=None, **{**settings.model_dump(), 'moyai_organization_id': identity})
        with pytest.raises(DatabaseError, match='different organization'):
            create_app(changed)


def test_roles_scim_profiles_and_audit_stay_in_own_deployment(deployments):
    (north, a), (south, b) = deployments
    role = a.post('/api/admin/roles', json={'id': 'limited-north', 'name': 'North reader',
        'permissions': ['workspace.read', 'sessions.read']})
    assert role.status_code == 201, role.text
    assigned = a.put('/api/admin/role-assignments', json={'email': 'reader@example.com', 'role_id': 'limited-north'})
    assert assigned.status_code == 200, assigned.text
    assert 'sessions.create' not in north.state.user_roles.permissions('reader@example.com')
    assert 'sessions.create' in south.state.user_roles.permissions('reader@example.com')
    assert not any(item['id'] == 'limited-north' for item in b.get('/api/admin/roles').json()['roles'])
    north_profile = profile(a, 'North policy')
    south_profile = profile(b, 'South policy')
    assert [item['id'] for item in a.get('/api/security-profiles').json()] == [north_profile['id']]
    assert [item['id'] for item in b.get('/api/security-profiles').json()] == [south_profile['id']]
    token_a = a.post('/api/admin/scim/tokens', json={'label': 'North directory'}).json()['token']
    token_b = b.post('/api/admin/scim/tokens', json={'label': 'South directory'}).json()['token']
    user_a = a.post('/scim/v2/Users', headers={'Authorization': 'Bearer ' + token_a},
                    json={'userName': 'person@example.com', 'active': False})
    assert user_a.status_code == 201, user_a.text
    with north.state.store.connect() as conn:
        assert not north.state.user_roles.active_email_in(conn, 'person@example.com')
    with south.state.store.connect() as conn:
        assert south.state.user_roles.active_email_in(conn, 'person@example.com')
    assert b.get('/scim/v2/Users/' + user_a.json()['id'], headers={'Authorization': 'Bearer ' + token_b}).status_code == 404
    assert b.get('/scim/v2/Users', headers={'Authorization': 'Bearer ' + token_a}).status_code == 401
    assert b.get('/api/admin/scim').json()['users'] == []
    north_audit = a.get('/api/admin/governance/audit').json()['events']
    south_audit = b.get('/api/admin/governance/audit').json()['events']
    assert any(event['resource_id'] == north_profile['id'] for event in north_audit)
    assert not any(event['resource_id'] in {north_profile['id'], user_a.json()['id'], 'limited-north'} for event in south_audit)


def test_foreign_browser_cookie_audit_cursor_and_run_capability_rejected(deployments):
    (north, a), (south, b) = deployments
    profile(a, 'North first')
    profile(a, 'North second')
    profile(b, 'South policy')
    north_page = a.get('/api/admin/governance/audit', params={'limit': 1}).json()
    assert north_page['next_cursor']
    invalid_cursor = b.get('/api/admin/governance/audit', params={'cursor': north_page['next_cursor'], 'limit': 1})
    assert invalid_cursor.status_code == 422
    original = b.cookies.get('workspace_session')
    b.cookies.clear()
    b.cookies.set('workspace_session', a.cookies.get('workspace_session'))
    assert b.get('/api/admin/security-profiles').status_code == 401
    b.cookies.clear()
    b.cookies.set('workspace_session', original)
    run_a, run_b = run(a, 'North confidential work'), run(b, 'South confidential work')
    auth_a, auth_b = capability(north, run_a['id']), capability(south, run_b['id'])
    assert a.get('/broker/' + run_a['id'] + '/tools', headers=auth_a).status_code == 200
    assert b.get('/broker/' + run_b['id'] + '/tools', headers=auth_b).status_code == 200
    assert b.get('/broker/' + run_a['id'] + '/tools', headers=auth_a).status_code == 401
    assert b.get('/broker/' + run_b['id'] + '/tools', headers=auth_a).status_code == 401
    assert b.get('/api/runs/' + run_a['id']).status_code == 404
    assert [row['id'] for row in b.get('/api/runs').json()] == [run_b['id']]


def test_durable_capabilities_are_scoped_even_with_reused_key_and_ids(tmp_path):
    shared = Fernet.generate_key().decode()
    north = configured(tmp_path / 'north', 'north')
    south = configured(tmp_path / 'south', 'south')
    north.encryption_key = south.encryption_key = shared
    first = DurableRunner.token(SimpleNamespace(settings=north), 'same-run', 7)
    second = DurableRunner.token(SimpleNamespace(settings=south), 'same-run', 7)
    assert first != second


def test_unconfigured_direct_org_runtime_cannot_bypass_governance(tmp_path):
    from app.runner import RunManager
    from app.temporal_runtime import TemporalRunManager
    settings = configured(tmp_path / 'direct-worker', 'north')
    store = Store(settings.data_dir)
    try:
        OrganizationScope(store, settings)
        for manager in (RunManager, TemporalRunManager):
            with pytest.raises(DatabaseError, match='through create_app'):
                manager(store, settings)
    finally:
        store.close()


def test_identical_library_cursor_versions_include_organization():
    from app.library_views import page
    items = [{'id': 'shared-deterministic-id', 'revision': 1}, {'id': 'another-id', 'revision': 1}]
    identity = ['same-query', 'shared:password:admin', [(item['id'], item['revision']) for item in items]]
    _, paging = page(items, '', 1, identity, organization_id='north')
    assert paging['next']
    with pytest.raises(HTTPException) as error:
        page(items, paging['next'], 1, identity, organization_id='south')
    assert error.value.status_code == 409
    selected, _ = page(items, paging['next'], 1, identity, organization_id='north')
    assert selected == items[1:]


def test_modal_deployment_resources_are_separate_and_config_exports_org_id(tmp_path, monkeypatch):
    deployments = []
    for identity in ('north', 'south', ''):
        settings = configured(tmp_path / identity, identity) if identity else Settings(_env_file=None, data_dir=tmp_path / 'legacy')
        module = wrapper(monkeypatch, settings, 'organization_deployment_' + (identity or 'legacy'))
        assert module.ORGANIZATION_ID == identity
        exported = module.deployment_config(settings)
        assert exported['MOYAI_ORGANIZATION_ID'] == identity
        assert not {'PUBLIC_URL', 'DATA_DIR', 'CHECKPOINT_DIR', 'MODAL_VOLUME_NAME'} & exported.keys()
        deployments.append((module.APP_NAME, module.VOLUME_NAME, module.CONFIG_SECRET_NAME))
    assert all(left != right for left, right in zip(deployments[0], deployments[1]))
    assert deployments[2] == ('moyai', 'hermes-workspace-state', 'hermes-workspace-config')


def test_modal_container_imports_wrapper_with_only_stdlib_and_modal(tmp_path):
    # Modal mounts only the entrypoint file and imports it with the image's system
    # Python; the app package and its dependencies are not on that interpreter's path.
    shutil.copy(WRAPPER, tmp_path / 'deploy_modal.py')
    probe = '\n'.join((
        'import json, sys',
        'sys.path.insert(0, sys.argv[1])',
        "sys.modules.update(dict.fromkeys(('app', 'pydantic', 'pydantic_settings', 'dotenv', 'cryptography')))",
        'from modal._runtime.task_lifecycle_manager import _TaskLifecycleManager',
        '_TaskLifecycleManager._singleton = object()  # Modal sets this before importing user code.',
        'import deploy_modal as m',
        'print(json.dumps([m.ORGANIZATION_ID, m.APP_NAME, m.VOLUME_NAME, m.CONFIG_SECRET_NAME]))'))
    for identity, expected in (
            ('north', ['north', 'moyai-org-north', 'hermes-workspace-state-org-north', 'hermes-workspace-config-org-north']),
            ('', ['', 'moyai', 'hermes-workspace-state', 'hermes-workspace-config'])):
        environment = {'PATH': os.environ.get('PATH', ''), 'HOME': str(tmp_path), 'MOYAI_ORGANIZATION_ID': identity}
        result = subprocess.run([sys.executable, '-I', '-c', probe, str(tmp_path)], cwd=tmp_path, env=environment,
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout.strip().splitlines()[-1]) == expected


def test_modal_wrapper_scoped_name_copy_matches_application(tmp_path, monkeypatch):
    module = wrapper(monkeypatch, Settings(_env_file=None, data_dir=tmp_path), 'organization_deployment_names')
    for value, identity, maximum in (('moyai', 'north', 64), ('hermes-workspace-config', 'n' * 32, 64),
                                     ('a' * 70, 'acme', 64), ('saved-app-org-north', 'north', 64),
                                     ('a' * 60 + '-org-north', 'north', 64), ('name--', 'acme', 14),
                                     ('moyai-sessions-v1', 'acme', None), ('', 'acme', 64)):
        assert module.scoped_name(value, identity, maximum) == scoped_name(value, identity, maximum)
