"""Exercise provisioning through HTTP and the real transactional database."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
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


def statements(monkeypatch):
    import sqlite3
    from app.database import PostgresConnection, SQLiteConnection
    executed = []
    for kind, execute in ((SQLiteConnection, sqlite3.Connection.execute), (PostgresConnection, PostgresConnection.execute)):
        monkeypatch.setattr(kind, 'execute', lambda conn, *args, execute=execute: executed.append(args[0]) or execute(conn, *args))
    return executed


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


def test_only_administrators_issue_credentials_that_control_group_permissions(users_app):
    app, client = users_app
    sign_as(app, client, 'tin@berri.ai')
    assert client.post('/api/admin/roles', json={'id': 'provisioner', 'name': 'Provisioner', 'permissions': ['scim.manage']}).status_code == 201
    assert client.put('/api/admin/role-assignments', json={'email': 'maya@berri.ai', 'role_id': 'provisioner'}).status_code == 200
    issued = client.post('/api/admin/scim/tokens', json={'label': 'Directory'})
    assert issued.status_code == 200
    sign_as(app, client, 'maya@berri.ai')
    # A provisioning credential can add its holder to any granted group.
    assert client.get('/api/admin/scim').status_code == 200
    assert client.post('/api/admin/scim/tokens', json={'label': 'Escalation'}).status_code == 403
    assert len(app.state.store.rows('SELECT id FROM scim_tokens')) == 1
    assert client.delete('/api/admin/scim/tokens/' + issued.json()['id']).status_code == 204
    service = app.state.scim
    with app.state.store.connect() as conn:
        conn.begin_write()
        tin = service.write_in(conn, 'User', {'userName': 'tin@berri.ai'})
        for actor in ({'method': 'google', 'identity': {'email': 'maya@berri.ai'}, 'role': 'admin'},
                      {'method': 'local', 'role': 'member'}, {'method': 'cloudflare', 'identity': {'email': 'other@example.com'}, 'role': 'admin'}):
            with pytest.raises(HTTPException):
                service.require_admin_in(conn, actor)
        service.require_admin_in(conn, {'method': 'google', 'identity': {'email': 'Tin@berri.ai'}, 'role': 'admin'})
        service.require_admin_in(conn, {'method': 'password', 'role': 'admin'})
        with pytest.raises(HTTPException):
            service.require_admin_in(conn, {'role': 'admin'})
        # The write transaction rechecks a demotion or deactivation since admission.
        service.write_in(conn, 'User', {'userName': 'tin@berri.ai', 'active': False}, tin['id'])
        with pytest.raises(HTTPException):
            service.require_admin_in(conn, {'method': 'google', 'identity': {'email': 'tin@berri.ai'}, 'role': 'admin'})


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


def test_entra_member_removal_and_okta_rename_change_only_their_targets(provision):
    _, client, _ = provision
    first, second, third = user(client), user(client, 'two@example.com'), user(client, 'three@example.com')
    team = group(client, [first, second, third])
    path = '/scim/v2/Groups/' + team['id']
    # Entra's default PATCH removes one member with a value array.
    removed = patch(client, path, [{'op': 'Remove', 'path': 'members', 'value': [{'$ref': None, 'value': first['id']}]}])
    assert removed.status_code == 200, removed.text
    assert {item['value'] for item in client.get(path).json()['members']} == {second['id'], third['id']}
    assert patch(client, path, [{'op': 'remove', 'path': 'members', 'value': [{'value': first['id']}]}]).status_code == 200
    assert len(client.get(path).json()['members']) == 2
    invalid = patch(client, path, [{'op': 'remove', 'path': 'members', 'value': {'value': second['id']}}])
    assert invalid.status_code == 400 and invalid.json()['scimType'] == 'invalidValue'
    renamed = patch(client, path, [{'op': 'replace', 'value': {'id': team['id'], 'displayName': 'Engineering 2'}}])
    assert renamed.status_code == 200 and renamed.json()['displayName'] == 'Engineering 2'
    assert patch(client, path, [{'op': 'replace', 'value': {'id': first['id']}}]).json()['scimType'] == 'mutability'
    assert patch(client, path, [{'op': 'remove', 'path': 'members'}]).json()['members'] == []


def test_attribute_projection_matches_groups_without_loading_members(provision, monkeypatch):
    service, client, _ = provision
    person = user(client, name={'givenName': 'Pat'})
    team = group(client, [person], 'Eng')
    related, original = [], service.resource_in
    monkeypatch.setattr(service, 'resource_in', lambda *args, **kwargs: related.append(kwargs.get('related', True)) or original(*args, **kwargs))
    # Entra matches groups this way before creating or updating them.
    found = client.get('/scim/v2/Groups', params={'excludedAttributes': 'members', 'filter': 'displayName eq "Eng"'})
    assert found.status_code == 200, found.text
    assert set(found.json()['Resources'][0]) == {'schemas', 'id', 'meta', 'displayName'} and related == [False]
    single = client.get('/scim/v2/Groups/' + team['id'], params={'excludedAttributes': CORE + 'Group:Members'}).json()
    assert single['displayName'] == 'Eng' and 'members' not in single
    users = client.get('/scim/v2/Users', params={'attributes': 'userName, NAME'}).json()['Resources']
    assert users[0] == {'schemas': [CORE + 'User'], 'id': person['id'], 'userName': person['userName'],
                        'name': {'givenName': 'Pat'}, 'meta': person['meta']}
    kept = client.get('/scim/v2/Users/' + person['id'], params={'excludedAttributes': 'id,userName,name,groups,schemas'}).json()
    assert set(kept) == {'schemas', 'id', 'meta', 'userName', 'active'}
    changed = patch(client, '/scim/v2/Groups/' + team['id'] + '?excludedAttributes=members',
                    [{'op': 'replace', 'path': 'displayName', 'value': 'Platform'}])
    assert changed.status_code == 200 and 'members' not in changed.json()
    for params in ({'attributes': 'userName', 'excludedAttributes': 'name'}, {'attributes': 'password'},
                   {'excludedAttributes': 'name.givenName'}, {'attributes': ''}):
        for target in ('/scim/v2/Users', '/scim/v2/Users/' + person['id']):
            response = client.get(target, params=params)
            assert response.status_code == 400 and response.json()['scimType'] == 'invalidValue'


def test_group_writes_change_only_the_membership_delta(provision, monkeypatch):
    service, client, _ = provision
    stamp, ids = now(), [f'{index:032x}' for index in range(1200)]
    with service.store.connect() as conn:
        conn.begin_write()
        for identity in ids:
            conn.execute('''INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision)
                VALUES(?,'',?,'{}',1,'',?,?,1)''', (identity, identity + '@example.com', stamp, stamp))
    # More members than SQLite's historical 999 bound-variable limit.
    created = client.post('/scim/v2/Groups', json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[:1100]]})
    assert created.status_code == 201 and len(created.json()['members']) == 1100
    path = '/scim/v2/Groups/' + created.json()['id']
    executed = statements(monkeypatch)
    added = patch(client, path + '?excludedAttributes=members', [{'op': 'add', 'path': 'members', 'value': [{'value': ids[1100]}]}])
    assert added.status_code == 200 and 'members' not in added.json()
    assert len(executed) < 30, executed
    assert len(service.store.rows('SELECT user_id FROM scim_group_members')) == 1101
    # An invalid addition rolls back every removal and addition in the request.
    failed = client.put(path, json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[600:] + ['missing']]})
    assert failed.status_code == 400 and len(service.store.rows('SELECT user_id FROM scim_group_members')) == 1101
    replaced = client.put(path, json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[600:]]})
    assert replaced.status_code == 200 and {item['value'] for item in replaced.json()['members']} == set(ids[600:])
    assert {row['user_id'] for row in service.store.rows('SELECT user_id FROM scim_group_members')} == set(ids[600:])


def test_patch_merges_complex_name_and_appends_emails(provision):
    _, client, _ = provision
    person = user(client, name={'givenName': 'A', 'familyName': 'B'},
                  emails=[{'value': 'person@example.com', 'type': 'work', 'primary': True}])
    path = '/scim/v2/Users/' + person['id']
    result = patch(client, path, [{'op': 'replace', 'path': 'name', 'value': {'givenName': 'Z'}},
                                  {'op': 'add', 'value': {'name': {'middleName': 'Q'}}},
                                  {'op': 'add', 'path': 'emails', 'value': [{'value': 'PERSON@example.com', 'type': 'work'},
                                                                            {'value': 'home@example.com', 'type': 'home', 'primary': True}]}])
    assert result.status_code == 200, result.text
    assert result.json()['name'] == {'givenName': 'Z', 'familyName': 'B', 'middleName': 'Q'}
    assert result.json()['emails'] == [{'value': 'person@example.com', 'type': 'work', 'primary': False},
                                       {'value': 'home@example.com', 'type': 'home', 'primary': True}]
    replaced = patch(client, path, [{'op': 'replace', 'path': 'emails', 'value': [{'value': 'home@example.com'}]}])
    assert replaced.json()['emails'] == [{'value': 'home@example.com'}]
    invalid = patch(client, path, [{'op': 'add', 'path': 'emails', 'value': {'value': 'other@example.com'}}])
    assert invalid.status_code == 400 and invalid.json()['scimType'] == 'invalidValue'


def test_entra_string_booleans_deactivate_only_through_patch(provision):
    service, client, _ = provision
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    assert patch(client, path, [{'op': 'Replace', 'path': 'active', 'value': 'False'}]).json()['active'] is False
    with service.store.connect() as conn:
        assert not active_for_email_in(conn, person['userName'])
    assert patch(client, path, [{'op': 'replace', 'value': {'active': ' TRUE '}}]).json()['active'] is True
    with service.store.connect() as conn:
        assert active_for_email_in(conn, person['userName'])
    assert patch(client, path, [{'op': 'replace', 'path': 'active', 'value': 'no'}]).json()['scimType'] == 'invalidValue'
    assert client.put(path, json={'userName': person['userName'], 'active': 'false'}).status_code == 400


def test_handlers_query_the_database_off_the_event_loop(provision, monkeypatch):
    import asyncio
    service, client, _ = provision
    running, original = [], service.authenticate_in
    def authenticate_in(conn, request):
        try:
            running.append(bool(asyncio.get_running_loop()))
        except RuntimeError:
            running.append(False)
        return original(conn, request)
    monkeypatch.setattr(service, 'authenticate_in', authenticate_in)
    person = user(client)
    assert client.get('/scim/v2/Users/' + person['id']).status_code == 200
    assert client.get('/scim/v2/Users').status_code == 200
    assert client.get('/scim/v2/ServiceProviderConfig').status_code == 200
    assert patch(client, '/scim/v2/Users/' + person['id'], [{'op': 'replace', 'path': 'title', 'value': 'Lead'}]).status_code == 200
    assert client.delete('/scim/v2/Users/' + person['id']).status_code == 204
    assert len(running) >= 7 and not any(running)


@pytest.mark.asyncio
async def test_body_limit_stops_reading_declared_and_chunked_requests(provision):
    from starlette.requests import Request
    from app.scim import ScimError
    service, _, token = provision
    received = []
    async def receive():
        received.append(1)
        return {'type': 'http.request', 'body': b' ' * (1024 * 1024), 'more_body': True}
    def request(*headers):
        return Request({'type': 'http', 'method': 'POST', 'path': '/scim/v2/Users', 'query_string': b'',
                        'headers': [(b'authorization', ('Bearer ' + token).encode()), (b'content-type', MEDIA.encode()), *headers]}, receive)
    with pytest.raises(ScimError) as error:
        await service.body(request((b'content-length', str(3 * 1024 * 1024).encode())))
    assert error.value.status == 413 and not received
    # A chunked body has no declared length and would otherwise never end.
    with pytest.raises(ScimError) as error:
        await service.body(request())
    assert error.value.status == 413 and len(received) == 3


def test_active_lookup_uses_an_index_and_lists_tables_once_per_connection(provision, tmp_path):
    service, client, _ = provision
    user(client)
    with service.store.connect() as conn:
        listed, names = [], conn.table_names
        conn.table_names = lambda: listed.append(1) or names()
        assert active_for_email_in(conn, 'person@example.com')
        assert all(active_for_actor_in(conn, actor) for actor in ('google:a', 'google:b'))
        if service.store.database is None:
            # Tombstones keep the lookup off the live-only partial unique index.
            assert 'USING INDEX idx_scim_users_lookup' in ' '.join(row[3] for row in conn.execute('''EXPLAIN QUERY PLAN
                SELECT active,deleted_at FROM scim_users WHERE user_name=? ORDER BY (deleted_at='') DESC,updated_at DESC LIMIT 1''',
                ('person@example.com',)))
    assert len(listed) <= 1  # Once per connection; PostgreSQL caches it per schema.
    # Stores without provisioning tables keep unmanaged access on their own connections.
    unmanaged = Store(tmp_path / 'unmanaged')
    with unmanaged.connect() as conn:
        assert active_for_email_in(conn, 'person@example.com')


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
    run = service.store.create_run('Do work', '', 'modal', [], chat_enabled=True, user_id=actor)
    service.store.claim_message(run['id'])
    service.store.update_run(run['id'], status='running', token_hash='capability')
    caller = service.store.run(run['id'])
    assert patch(client, '/scim/v2/Users/' + target['id'], [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 200
    body = SimpleNamespace(request_id='revoked-dispatch', input_id=caller['active_message_id'],
                           name='github_create_pull_request', arguments={})
    with pytest.raises(ToolRejected) as error:
        ToolDispatch(service.store, caller, body).claim()
    assert error.value.status_code == 403
    assert error.value.detail == 'The executing user has been deactivated.'
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


@pytest.mark.asyncio
async def test_slack_lookup_backoff_and_transient_failures_retry_instead_of_dropping(provision):
    import time
    from app.slack import SlackSessions
    service, client, _ = provision
    user(client)  # Any provisioned user turns on the verified-sender requirement.
    resolved = []
    async def resolve(row, team):
        resolved.append(row['id'])
        service.store.execute("UPDATE users SET link_status='unavailable',profile_next_check=? WHERE id=?",
                              (int(time.time()) + 300, row['id']))
    owner = SimpleNamespace(store=service.store, settings=service.security.settings,
                            identities=SimpleNamespace(status=lambda: {'ready': True}, resolve=resolve))
    # A transient lookup failure is reported as unknown, never as a denial.
    assert await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U22222222') is None
    assert await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U22222222') is None
    assert resolved == ['slack:T12345678:U22222222']  # The backoff is honored per event.
    service.store.execute("UPDATE users SET link_status='ineligible' WHERE id=?", ('slack:T12345678:U22222222',))
    assert await SlackSessions.provisioning_sender_allowed(owner, 'T12345678', 'U22222222') is False
    assert len(resolved) == 1
    async def unknown(team, sender):
        return None
    sessions = SimpleNamespace(provisioning_sender_allowed=unknown)
    fields = dict(team='T12345678', event_id='EvRetry', channel='C12345678', root='', user='U22222222',
                  prompt='Do work', mentioned=True, direct_message=False, missing_cloud=[])
    with pytest.raises(HTTPException) as error:
        await SlackSessions.accept_message(sessions, ts=f'{time.time():.6f}', **fields)
    assert error.value.status_code == 503  # The inbox or Slack retries; nothing was admitted.
    assert await SlackSessions.accept_message(sessions, ts=f'{time.time() - 3600:.6f}', **fields) is None
