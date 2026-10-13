"""Exercise provisioning through HTTP and the real transactional database."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Store, now
from app.scim import API, CORE, MEDIA, Scim, active_for_actor_in, active_for_email_in
from app.security import Security
from app.user_roles import UserRoles
from test_user_roles import users_app, sign_as


@pytest.fixture
def provision(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    store = Store(settings.data_dir)
    roles = UserRoles(store, settings)
    security = Security(settings, roles)
    service = Scim(store, security)
    app = FastAPI()
    app.include_router(service.routes())
    app.include_router(service.admin_routes())
    with TestClient(app, base_url=settings.public_url) as client:
        response = JSONResponse({})
        sid = security.new_session(response, local=True)
        cookie = response.headers['set-cookie'].split('workspace_session=')[1].split(';')[0]
        client.cookies.set('workspace_session', cookie)
        client.headers.update({'Origin': security.origin, 'X-CSRF-Token': security.csrf(sid)})
        issued = client.post('/api/admin/scim/tokens', json={'label': 'Directory provider'})
        assert issued.status_code == 200
        token = issued.json()['token']
        client.headers['Authorization'] = 'Bearer ' + token
        yield service, client, token


def user(client, email='person@example.com', **extra):
    response = client.post('/scim/v2/Users', json={'schemas': [CORE + 'User'], 'userName': email, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def group(client, members=(), name='Engineering', **extra):
    response = client.post('/scim/v2/Groups', json={'schemas': [CORE + 'Group'], 'displayName': name,
                                                'members': [{'value': member['id']} for member in members], **extra})
    assert response.status_code == 201, response.text
    return response.json()


def patch(client, path, operations):
    return client.patch(path, json={'schemas': [API + 'PatchOp'], 'Operations': operations})


def test_credentials_are_one_time_hashed_revocable_and_scim_rejects_cookies(provision):
    service, client, token = provision
    saved = dict(service.store.rows('SELECT * FROM scim_tokens')[0])
    assert saved['token_hash'] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in str(saved)
    directory = client.get('/api/admin/scim').json()
    assert token not in str(directory)
    assert 'token_hash' not in str(directory)
    client.headers.pop('Authorization')
    # The privileged browser cookie cannot authenticate the provisioning API.
    response = client.get('/scim/v2/Users')
    assert response.status_code == 401 and response.json()['schemas'] == [API + 'Error']
    assert response.headers['www-authenticate'] == 'Bearer'
    client.headers['Authorization'] = 'Bearer ' + token[:-1] + ('A' if token[-1] != 'A' else 'B')
    assert client.get('/scim/v2/Users').status_code == 401
    client.headers['Authorization'] = 'Bearer ' + token
    assert client.get('/scim/v2/Users').status_code == 200
    assert client.delete('/api/admin/scim/tokens/' + saved['id']).status_code == 204
    assert client.get('/scim/v2/Users').status_code == 401
    assert client.post('/scim/v2/Users', json={'userName': 'next@example.com'}).status_code == 401
    assert client.delete('/api/admin/scim/tokens/' + saved['id']).status_code == 204


def test_credential_admin_management_enforces_csrf_and_live_role(provision):
    service, client, _ = provision
    client.headers['X-CSRF-Token'] = 'invalid'
    assert client.post('/api/admin/scim/tokens', json={'label': 'bad'}).status_code == 403
    assert len(service.store.rows('SELECT id FROM scim_tokens')) == 1
    response = JSONResponse({})
    sid = service.security.new_session(response, role='member', local=True)
    client.cookies.clear()
    client.cookies.set('workspace_session', response.headers['set-cookie'].split('workspace_session=')[1].split(';')[0])
    client.headers['X-CSRF-Token'] = service.security.csrf(sid)
    assert client.get('/api/admin/scim').status_code == 403
    assert client.post('/api/admin/scim/tokens', json={'label': 'bad'}).status_code == 403


def test_discovery_and_explicit_supported_capabilities(provision):
    _, client, _ = provision
    config = client.get('/scim/v2/ServiceProviderConfig')
    assert config.headers['content-type'] == MEDIA
    assert config.json()['patch']['supported']
    assert config.json()['filter'] == {'supported': True, 'maxResults': 100}
    assert not config.json()['bulk']['supported'] and not config.json()['etag']['supported']
    types = client.get('/scim/v2/ResourceTypes').json()
    assert {item['id'] for item in types['Resources']} == {'User', 'Group'}
    schema = client.get('/scim/v2/Schemas/' + CORE + 'User').json()
    username = next(item for item in schema['attributes'] if item['name'] == 'userName')
    assert username['required'] and username['mutability'] == 'immutable'
    assert client.get('/scim/v2/Schemas/not-a-schema').status_code == 404


def test_users_creation_filter_pagination_uniqueness_and_put(provision):
    service, client, _ = provision
    first = user(client, 'Person@EXAMPLE.com', externalId='directory-1', displayName='Person',
                 name={'givenName': 'Pat'}, emails=[{'value': 'person@example.com', 'primary': True, 'type': 'work'}])
    second = user(client, 'two@example.com')
    assert first['userName'] == 'person@example.com'
    assert first['meta']['location'].endswith('/Users/' + first['id'])
    by_name = client.get('/scim/v2/Users', params={'filter': 'userName eq "PERSON@example.com"'}).json()
    assert by_name['totalResults'] == 1 and by_name['Resources'][0]['id'] == first['id']
    assert client.get('/scim/v2/Users', params={'filter': 'externalId eq "directory-1"'}).json()['totalResults'] == 1
    page = client.get('/scim/v2/Users', params={'startIndex': 2, 'count': 1}).json()
    assert page['totalResults'] == 2 and page['itemsPerPage'] == 1 and page['startIndex'] == 2
    assert client.get('/scim/v2/Users', params={'count': 0}).json()['Resources'] == []
    duplicate = client.post('/scim/v2/Users', json={'userName': 'PERSON@example.com'})
    assert duplicate.status_code == 409 and duplicate.json()['scimType'] == 'uniqueness'
    assert client.post('/scim/v2/Users', json={'userName': 'three@example.com', 'externalId': 'directory-1'}).status_code == 409
    result = client.put('/scim/v2/Users/' + first['id'], json={'schemas': [CORE + 'User'],
                        'userName': first['userName'], 'displayName': 'Updated', 'active': False})
    assert result.status_code == 200 and not result.json()['active']
    assert 'name' not in result.json() and 'emails' not in result.json() and 'externalId' not in result.json()
    with service.store.connect() as conn:
        assert not active_for_email_in(conn, first['userName'])
        assert active_for_email_in(conn, second['userName'])


@pytest.mark.parametrize('expression', ['userName co "person"', 'userName eq "person@example.com" or active eq true',
                                         'password eq "x"', 'active eq "false"', 'userName eq true'])
def test_unsupported_filters_fail_explicitly(provision, expression):
    _, client, _ = provision
    response = client.get('/scim/v2/Users', params={'filter': expression})
    assert response.status_code == 400 and response.json()['scimType'] == 'invalidFilter'


def test_group_membership_patch_is_atomic_and_user_groups_are_readonly(provision):
    service, client, _ = provision
    first, second = user(client), user(client, 'two@example.com')
    team = group(client, [first])
    path = '/scim/v2/Groups/' + team['id']
    response = patch(client, path, [{'op': 'add', 'path': 'members', 'value': [{'value': second['id']}]},
                                    {'op': 'replace', 'path': 'displayName', 'value': 'Platform'}])
    assert response.status_code == 200
    assert {item['value'] for item in response.json()['members']} == {first['id'], second['id']}
    assert client.get('/scim/v2/Users/' + second['id']).json()['groups'][0]['display'] == 'Platform'
    before = client.get(path).json()
    failed = patch(client, path, [{'op': 'replace', 'path': 'displayName', 'value': 'Wrong'},
                                  {'op': 'add', 'path': 'members', 'value': [{'value': 'missing'}]}])
    assert failed.status_code == 400 and client.get(path).json() == before
    assert len(service.store.rows('SELECT * FROM scim_group_members')) == 2
    removed = patch(client, path, [{'op': 'remove', 'path': 'members[value eq "' + first['id'] + '"]'}])
    assert removed.status_code == 200 and [item['value'] for item in removed.json()['members']] == [second['id']]
    assert client.get('/scim/v2/Users/' + first['id']).json()['groups'] == []
    invalid = patch(client, '/scim/v2/Users/' + first['id'], [{'op': 'replace', 'path': 'groups', 'value': []}])
    assert invalid.status_code == 400 and invalid.json()['scimType'] == 'mutability'
    assert client.delete(path).status_code == 204
    assert client.get(path).status_code == 404 and not service.store.rows('SELECT * FROM scim_group_members')


def test_patch_deactivation_tombstone_reactivation_and_slack_identity(provision):
    service, client, _ = provision
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    actor = service.store.identity({'method': 'google', 'identity': {'email': person['userName'], 'sub': 'person', 'name': 'Person'}})
    stamp = now()
    service.store.execute('INSERT INTO users(id,kind,email,name,linked_user_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',
                          ('slack:T:U', 'slack', '', 'Person', actor, stamp, stamp))
    changed = patch(client, path, [{'op': 'replace', 'path': 'active', 'value': False},
                                  {'op': 'replace', 'path': 'name.givenName', 'value': 'Pat'}])
    assert changed.status_code == 200 and changed.json()['name']['givenName'] == 'Pat'
    with service.store.connect() as conn:
        assert not active_for_actor_in(conn, actor) and not active_for_actor_in(conn, 'slack:T:U')
        assert active_for_email_in(conn, 'unmanaged@example.com')
    assert patch(client, path, [{'op': 'replace', 'value': {'active': True}}]).status_code == 200
    with service.store.connect() as conn:
        assert active_for_actor_in(conn, actor)
    assert client.delete(path).status_code == 204
    assert client.get(path).status_code == 404
    assert client.get('/scim/v2/Users', params={'filter': 'userName eq "person@example.com"'}).json()['totalResults'] == 0
    with service.store.connect() as conn:
        assert not active_for_actor_in(conn, actor) and not active_for_actor_in(conn, 'slack:T:U')
    # A new provisioning lifecycle gets a new stable id and can re-enable access.
    replacement = user(client)
    assert replacement['id'] != person['id']
    with service.store.connect() as conn:
        assert active_for_actor_in(conn, actor)


def test_last_active_administrator_cannot_be_deprovisioned(provision):
    service, client, _ = provision
    owner = user(client, 'owner@example.com')
    path = '/scim/v2/Users/' + owner['id']
    assert patch(client, path, [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 409
    assert client.delete(path).status_code == 409
    assert client.get(path).json()['active']
    assert not service.store.rows("SELECT 1 FROM scim_audit WHERE action IN ('patch','delete')")


def test_malformed_payloads_and_immutable_identity_do_not_partially_write(provision):
    service, client, _ = provision
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    assert patch(client, path, [{'op': 'replace', 'path': 'userName', 'value': 'other@example.com'}]).json()['scimType'] == 'mutability'
    assert client.post('/scim/v2/Users', json={'userName': 'other@example.com', 'active': 'false'}).status_code == 400
    assert client.post('/scim/v2/Users', json={'userName': 'other@example.com', 'password': 'hidden'}).status_code == 400
    malformed = client.post('/scim/v2/Users', content='{', headers={'content-type': MEDIA})
    assert malformed.status_code == 400 and malformed.json()['scimType'] == 'invalidSyntax'
    assert client.post('/scim/v2/Users', content='body', headers={'content-type': 'text/plain'}).status_code == 415
    assert client.get('/scim/v2/Users', params={'sortBy': 'userName'}).status_code == 400
    assert len(service.store.rows("SELECT id FROM scim_users WHERE deleted_at=''")) == 1


def test_existing_google_session_is_revoked_by_provisioning_without_changing_login(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    issued = client.post('/api/admin/scim/tokens', json={'label': 'Identity provider'})
    assert issued.status_code == 200
    client.headers['Authorization'] = 'Bearer ' + issued.json()['token']
    target = user(client, 'maya@berri.ai')
    sign_as(app, client, 'maya@berri.ai')
    assert client.get('/api/session').json()['authenticated']
    cookie = client.cookies.get('workspace_session')
    assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 200
    assert client.cookies.get('workspace_session') == cookie
    assert not client.get('/api/session').json()['authenticated']
    assert client.get('/api/runs').status_code == 401
    assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': True}]).status_code == 200
    assert client.get('/api/session').json()['authenticated']


@pytest.mark.asyncio
async def test_slack_intake_rechecks_known_sender_and_resolves_unknown_profiles(provision):
    from app.slack import SlackSessions
    from app.slack_chat import SlackChat
    service, client, _ = provision
    target = user(client, active=False)
    stamp = now()
    actor = 'slack:T12345678:U12345678'
    service.store.execute('INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                          (actor, 'slack', target['userName'], 'Person', stamp, stamp))
    owner = SimpleNamespace(store=service.store, settings=service.security.settings, identities=None)
    assert not await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U12345678')
    chat = SlackChat(owner)
    assert chat.accept(team='T12345678', event_id='EvInactive', channel='C12345678',
                       ts='1790719000.123456', root='1790719000.123456', user='U12345678',
                       prompt='Do work', mentioned=True, missing_cloud=[]) is None
    assert not service.store.rows('SELECT id FROM runs')
    # Unknown providers cannot skip the deactivation guard through JIT linking.
    assert not await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U87654321')
    resolved = []
    async def resolve(row, team):
        resolved.append((row['id'], team))
        service.store.execute('UPDATE users SET email=?,profile_eligible=1 WHERE id=?', (target['userName'], row['id']))
    owner.identities = SimpleNamespace(status=lambda: {'ready': True}, resolve=resolve)
    assert not await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U87654321')
    assert resolved == [('slack:T12345678:U87654321', 'T12345678')]
    assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': True}]).status_code == 200
    assert await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U87654321')


def test_deactivation_rejects_authenticated_tool_dispatch_before_action(provision):
    from app.tool_dispatch import ToolDispatch, ToolRejected
    service, client, _ = provision
    target = user(client)
    actor = service.store.identity({'method': 'google', 'identity': {'email': target['userName'], 'sub': 'person'}})
    run = service.store.create_run('Do work', '', 'modal', [], user_id=actor)
    service.store.update_run(run['id'], status='running', token_hash='capability')
    caller = service.store.run(run['id'])
    assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 200
    body = SimpleNamespace(request_id='revoked-dispatch', input_id=1, name='github_create_pull_request', arguments={})
    with pytest.raises(ToolRejected) as error:
        ToolDispatch(service.store, caller, body).claim()
    assert error.value.status_code == 403
    assert not service.store.rows("SELECT id FROM events WHERE kind='tool_dispatch'")


def test_concurrent_deactivation_preserves_one_active_administrator(provision):
    from app.scim import ScimError
    service, client, _ = provision
    service.security.settings.google_admin_emails = 'owner@example.com,second@example.com'
    people = [user(client, 'owner@example.com'), user(client, 'second@example.com')]
    barrier = Barrier(2)
    def deactivate(person):
        try:
            with service.store.connect() as conn:
                barrier.wait(timeout=5)
                conn.begin_write()
                service.write_in(conn, 'User', {'userName': person['userName'], 'active': False}, person['id'])
            return 200
        except ScimError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(deactivate, people))
    assert sorted(outcomes) == [200, 409]
    assert len(service.store.rows("SELECT id FROM scim_users WHERE active=1 AND deleted_at=''")) == 1
    with service.store.connect() as conn:
        assert len(service.security.user_roles.admins_in(conn)) == 1


def test_credential_revocation_between_parse_and_write_cannot_admit_mutation(provision, monkeypatch):
    service, client, _ = provision
    original = service.body
    async def revoke_after_parse(request):
        document = await original(request)
        service.store.execute("UPDATE scim_tokens SET revoked_at=?", (now(),))
        return document
    monkeypatch.setattr(service, 'body', revoke_after_parse)
    response = client.post('/scim/v2/Users', json={'userName': 'race@example.com'})
    assert response.status_code == 401 and response.json()['schemas'] == [API + 'Error']
    assert not service.store.rows('SELECT id FROM scim_users')
    assert not service.store.rows("SELECT id FROM scim_audit WHERE action='create'")
