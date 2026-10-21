"""SCIM provisioning through HTTP and the real transactional database (SQLite or --postgres-backend)."""
import hashlib
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from app import scim as scim_module
from app.config import Settings
from app.database import DatabaseBusyError
from app.db import Store
from app.enterprise_roles import (
    GovernanceActor,
    GovernanceForbidden,
    GovernanceInvalid,
    GroupRoleChange,
    RoleCreate,
    scim_state_in,
)
from app.governance_audit import timestamp
from app.permissions import MEMBER_PERMISSIONS
from app.scim import API, CORE, MEDIA, Scim, ScimError, scim_router
from app.user_roles import UserRoles
from fastapi import FastAPI
from fastapi.testclient import TestClient

OWNER = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin', kind='individual')
PATCH = API + 'PatchOp'
ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'


@pytest.fixture
def provision(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    store = Store(tmp_path)
    try:
        roles = UserRoles(store, settings)
        service = Scim(store, roles, base_url='http://localhost:8787/scim/v2')
        record, token = service.create_token('Directory provider', OWNER)
        app = FastAPI()
        app.include_router(scim_router(service))
        with TestClient(app, base_url='http://localhost:8787') as client:
            client.headers['Authorization'] = 'Bearer ' + token
            yield SimpleNamespace(service=service, client=client, token=token, record=record, store=store,
                                  roles=roles, settings=settings)
    finally:
        store.close()


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
    return client.patch(path, json={'schemas': [PATCH], 'Operations': operations})


def scim_type(response, status=400):
    assert response.status_code == status, response.text
    assert response.headers['content-type'] == MEDIA and response.json()['schemas'] == [API + 'Error']
    return response.json().get('scimType')


def statements(monkeypatch):
    import sqlite3

    from app.database import PostgresConnection, SQLiteConnection
    executed = []
    for kind, execute in ((SQLiteConnection, sqlite3.Connection.execute), (PostgresConnection, PostgresConnection.execute)):
        monkeypatch.setattr(kind, 'execute', lambda conn, *args, execute=execute: executed.append(args[0]) or execute(conn, *args))
    return executed


def active(provision, email):
    with provision.store.connect() as conn:
        return scim_state_in(conn, email) is not False


def scim_events(provision):
    return provision.store.rows("""SELECT action,actor,resource_type,resource_id,details FROM governance_audit_events
        WHERE resource_type IN ('scim_user','scim_group','scim_token') ORDER BY created_at,id""")


def test_tokens_are_one_time_hashed_revocable_and_bearer_only(provision):
    service, client, token = provision.service, provision.client, provision.token
    saved = dict(provision.store.rows('SELECT * FROM scim_tokens')[0])
    assert saved['token_hash'] == hashlib.sha256(token.encode()).hexdigest() and token not in str(saved)
    assert saved['prefix'] == token[:19] and saved['created_by'] == 'owner@example.com'
    directory = service.directory(actor=OWNER)
    assert token not in json.dumps(directory) and saved['token_hash'] not in json.dumps(directory)
    assert set(directory['tokens'][0]) == {'id', 'label', 'prefix', 'created_at', 'created_by', 'last_used_at', 'revoked_at'}
    client.headers.pop('Authorization')
    client.cookies.set('workspace_session', 'any-browser-session')
    response = client.get('/scim/v2/Users')
    assert scim_type(response, 401) is None and response.headers['www-authenticate'] == 'Bearer'
    for header in ('Bearer ' + token[:-1] + ('A' if token[-1] != 'A' else 'B'), 'Basic ' + token, token):
        client.headers['Authorization'] = header
        assert client.get('/scim/v2/Users').status_code == 401
    client.headers['Authorization'] = 'bearer ' + token  # The scheme is case-insensitive.
    assert client.get('/scim/v2/Users').status_code == 200
    revoked = service.revoke_token(saved['id'], OWNER)
    assert revoked['revoked_at'] and service.revoke_token(saved['id'], OWNER) == revoked
    assert client.get('/scim/v2/Users').status_code == 401
    assert client.post('/scim/v2/Users', json={'userName': 'next@example.com'}).status_code == 401
    assert [row['action'] for row in scim_events(provision)] == ['scim_token.created', 'scim_token.revoked']
    with pytest.raises(GovernanceInvalid):
        service.create_token('', OWNER)
    with pytest.raises(GovernanceInvalid):
        service.create_token('x' * 81, OWNER)


def test_token_use_is_recorded_at_most_once_per_interval(provision, monkeypatch):
    client, store = provision.client, provision.store
    assert store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at'] == ''
    assert client.get('/scim/v2/Users').status_code == 200
    first = store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at']
    assert first
    executed = statements(monkeypatch)
    for _ in range(3):
        assert client.get('/scim/v2/Users').status_code == 200
    assert store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at'] == first
    assert not any('UPDATE scim_tokens' in statement for statement in executed)
    monkeypatch.setattr(scim_module, 'TOKEN_USE_INTERVAL', scim_module.timedelta(0))
    user(client)
    assert store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at'] > first


def test_only_builtin_administrators_create_tokens_and_delegates_revoke(provision):
    service, roles = provision.service, provision.roles
    roles.enterprise.create(RoleCreate(id='provisioner', name='Provisioner', permissions=['scim.manage']), OWNER)
    from app.enterprise_roles import RoleAssignment
    roles.enterprise.assign(RoleAssignment(email='maya@example.com', role_id='provisioner'), OWNER)
    maya = GovernanceActor(id='google:maya', email='maya@example.com', kind='individual')
    # A provisioning credential controls membership, group grants and deactivation.
    with pytest.raises(GovernanceForbidden):
        service.create_token('Escalation', maya)
    assert service.directory(actor=maya)['can_create_tokens'] is False
    assert service.directory(actor=OWNER)['can_create_tokens'] is True
    with pytest.raises(GovernanceForbidden):
        service.directory(actor=GovernanceActor(id='google:plain', email='plain@example.com', kind='individual'))
    record, _ = service.create_token('Second', OWNER)
    assert service.revoke_token(record['id'], maya)['revoked_at']
    # The writer rechecks: a deactivated administrator can no longer issue credentials.
    owner = user(provision.client, 'owner@example.com')
    provision.settings.google_admin_emails = 'owner@example.com,second@example.com'
    user(provision.client, 'second@example.com')
    assert patch(provision.client, '/scim/v2/Users/' + owner['id'],
                 [{'op': 'replace', 'path': 'active', 'value': False}]).status_code == 200
    with pytest.raises(GovernanceForbidden):
        service.create_token('Late', OWNER)


def test_discovery_and_explicit_supported_capabilities(provision):
    client = provision.client
    config = client.get('/scim/v2/ServiceProviderConfig')
    assert config.headers['content-type'] == MEDIA and config.headers['cache-control'] == 'no-store'
    assert config.json()['patch']['supported'] and config.json()['filter'] == {'supported': True, 'maxResults': 100}
    assert not config.json()['bulk']['supported'] and not config.json()['etag']['supported']
    assert {item['id'] for item in client.get('/scim/v2/ResourceTypes').json()['Resources']} == {'User', 'Group'}
    schema = client.get('/scim/v2/Schemas/' + CORE + 'User').json()
    username = next(item for item in schema['attributes'] if item['name'] == 'userName')
    assert username['required'] and username['mutability'] == 'immutable'
    assert scim_type(client.get('/scim/v2/Schemas/not-a-schema'), 404) is None


def test_users_creation_filter_pagination_uniqueness_and_put(provision):
    client = provision.client
    first = user(client, 'Person@EXAMPLE.com', externalId='directory-1', displayName='Person',
                 name={'givenName': 'Pat'}, emails=[{'value': 'person@example.com', 'primary': True, 'type': 'work'}])
    second = user(client, 'two@example.com')
    assert first['userName'] == 'person@example.com' and first['meta']['location'].endswith('/Users/' + first['id'])
    by_name = client.get('/scim/v2/Users', params={'filter': 'userName eq "PERSON@example.com"'}).json()
    assert by_name['totalResults'] == 1 and by_name['Resources'][0]['id'] == first['id']
    assert client.get('/scim/v2/Users', params={'filter': 'externalId eq "directory-1"'}).json()['totalResults'] == 1
    page = client.get('/scim/v2/Users', params={'startIndex': 2, 'count': 1}).json()
    assert page['totalResults'] == 2 and page['itemsPerPage'] == 1 and page['startIndex'] == 2
    assert client.get('/scim/v2/Users', params={'count': 0}).json()['Resources'] == []
    assert scim_type(client.post('/scim/v2/Users', json={'userName': 'PERSON@example.com'}), 409) == 'uniqueness'
    assert scim_type(client.post('/scim/v2/Users', json={'userName': 'three@example.com', 'externalId': 'directory-1'}),
                     409) == 'uniqueness'
    result = client.put('/scim/v2/Users/' + first['id'], json={'schemas': [CORE + 'User'],
                        'userName': first['userName'], 'displayName': 'Updated', 'active': False})
    assert result.status_code == 200 and not result.json()['active']
    assert 'name' not in result.json() and 'emails' not in result.json() and 'externalId' not in result.json()
    assert not active(provision, first['userName']) and active(provision, second['userName'])
    assert active(provision, 'unmanaged@example.com')


@pytest.mark.parametrize('expression', ['userName co "person"', 'userName eq "person@example.com" or active eq true',
                                        'password eq "x"', 'active eq "false"', 'userName eq true', '', '   '])
def test_unsupported_and_empty_filters_fail_explicitly(provision, expression):
    user(provision.client)
    response = provision.client.get('/scim/v2/Users', params={'filter': expression})
    # Regression: an empty filter= silently returned the whole directory.
    assert scim_type(response) == 'invalidFilter'


@pytest.mark.parametrize('start', ['100000000000000000000', str(2 ** 63 + 1), '9' * 4000])
def test_oversized_start_index_is_an_empty_page(provision, start):
    """Regression: an unbounded OFFSET raised a non-SCIM 500."""
    user(provision.client)
    response = provision.client.get('/scim/v2/Users', params={'startIndex': start})
    assert response.status_code == 200, response.text
    assert response.json()['totalResults'] == 1 and response.json()['Resources'] == []
    assert provision.client.get('/scim/v2/Users', params={'startIndex': '-5'}).json()['startIndex'] == 1
    assert scim_type(provision.client.get('/scim/v2/Users', params={'startIndex': '9' * 5000})) == 'invalidValue'


def test_group_membership_patch_is_atomic_and_user_groups_are_readonly(provision):
    client, store = provision.client, provision.store
    first, second = user(client), user(client, 'two@example.com')
    team = group(client, [first])
    path = '/scim/v2/Groups/' + team['id']
    response = patch(client, path, [{'op': 'add', 'path': 'members', 'value': [{'value': second['id']}]},
                                    {'op': 'replace', 'path': 'displayName', 'value': 'Platform'}])
    assert response.status_code == 204 and not response.content
    assert {item['value'] for item in client.get(path).json()['members']} == {first['id'], second['id']}
    assert client.get('/scim/v2/Users/' + second['id']).json()['groups'][0]['display'] == 'Platform'
    before = client.get(path).json()
    failed = patch(client, path, [{'op': 'replace', 'path': 'displayName', 'value': 'Wrong'},
                                  {'op': 'add', 'path': 'members', 'value': [{'value': 'missing'}]}])
    assert scim_type(failed) == 'invalidValue' and client.get(path).json() == before
    assert len(store.rows('SELECT * FROM scim_group_members')) == 2
    removed = patch(client, path, [{'op': 'remove', 'path': 'members[value eq "' + first['id'] + '"]'}])
    assert removed.status_code == 204 and [item['value'] for item in client.get(path).json()['members']] == [second['id']]
    assert scim_type(patch(client, path, [{'op': 'remove', 'path': 'members[value eq "' + first['id'] + '"]'}])) == 'noTarget'
    assert client.get('/scim/v2/Users/' + first['id']).json()['groups'] == []
    assert scim_type(patch(client, '/scim/v2/Users/' + first['id'],
                           [{'op': 'replace', 'path': 'groups', 'value': []}])) == 'mutability'
    assert scim_type(client.post('/scim/v2/Groups', json={'displayName': 'PLATFORM'}), 409) == 'uniqueness'
    assert client.delete(path).status_code == 204
    assert client.get(path).status_code == 404 and not store.rows('SELECT * FROM scim_group_members')


def test_entra_member_removal_and_okta_rename_change_only_their_targets(provision):
    client = provision.client
    first, second, third = user(client), user(client, 'two@example.com'), user(client, 'three@example.com')
    team = group(client, [first, second, third])
    path = '/scim/v2/Groups/' + team['id']
    removed = patch(client, path, [{'op': 'Remove', 'path': 'members', 'value': [{'$ref': None, 'value': first['id']}]}])
    assert removed.status_code == 204, removed.text
    assert {item['value'] for item in client.get(path).json()['members']} == {second['id'], third['id']}
    assert patch(client, path, [{'op': 'remove', 'path': 'members', 'value': [{'value': first['id']}]}]).status_code == 204
    assert len(client.get(path).json()['members']) == 2
    assert scim_type(patch(client, path, [{'op': 'remove', 'path': 'members', 'value': {'value': second['id']}}])) == 'invalidValue'
    renamed = patch(client, path, [{'op': 'replace', 'value': {'id': team['id'], 'displayName': 'Engineering 2'}}])
    assert renamed.status_code == 204 and client.get(path).json()['displayName'] == 'Engineering 2'
    assert scim_type(patch(client, path, [{'op': 'replace', 'value': {'id': first['id']}}])) == 'mutability'
    assert patch(client, path, [{'op': 'remove', 'path': 'members'}]).status_code == 204
    assert client.get(path).json()['members'] == []


def test_entra_filtered_email_and_extension_paths_never_void_a_deactivation(provision):
    """Regression: unsupported Entra shapes failed the whole PATCH, so `active: False` was lost."""
    client = provision.client
    # Entra's create includes the enterprise extension, addresses and phone numbers.
    person = user(client, 'leaver@example.com', schemas=[CORE + 'User', ENTERPRISE], name={'givenName': 'Lee'},
                  emails=[{'value': 'leaver@example.com', 'type': 'work', 'primary': True}],
                  phoneNumbers=[{'type': 'work', 'value': '+1 555 0100'}], addresses=[{'type': 'work', 'formatted': 'HQ'}],
                  **{ENTERPRISE: {'employeeNumber': '42', 'department': 'Sales'}})
    assert set(person) >= {'name', 'emails'} and 'phoneNumbers' not in person and ENTERPRISE not in person
    path = '/scim/v2/Users/' + person['id']
    for operations in (
        [{'op': 'Replace', 'path': 'emails[type eq "work"].value', 'value': 'leaver.new@example.com'},
         {'op': 'Replace', 'path': 'active', 'value': 'False'}],
        [{'op': 'Replace', 'path': 'active', 'value': 'False'},
         {'op': 'Replace', 'path': ENTERPRISE + ':employeeNumber', 'value': '43'},
         {'op': 'Replace', 'path': 'phoneNumbers[type eq "mobile"].value', 'value': '+1 555 0101'},
         {'op': 'Add', 'path': 'addresses[type eq "work"].formatted', 'value': 'Remote'}],
        [{'op': 'Replace', 'value': {'active': False, 'name.familyName': 'Leaver',
                                     'emails[type eq "work"].value': 'leaver.new@example.com',
                                     ENTERPRISE + ':department': 'Ops'}}],
    ):
        assert patch(client, path, [{'op': 'replace', 'path': 'active', 'value': True}]).status_code == 200
        response = patch(client, path, operations)
        assert response.status_code == 200, (operations, response.text)
        assert response.json()['active'] is False and not active(provision, 'leaver@example.com')
    current = client.get(path).json()
    assert current['emails'] == [{'value': 'leaver.new@example.com', 'type': 'work', 'primary': True}]
    assert current['name'] == {'givenName': 'Lee', 'familyName': 'Leaver'}
    # A new work email is added when none of that type exists; removal by filter is idempotent.
    added = patch(client, path, [{'op': 'add', 'path': 'emails[type eq "home"].value', 'value': 'lee@example.com'},
                                 {'op': 'remove', 'path': 'emails[type eq "other"]'}])
    assert {item['type']: item['value'] for item in added.json()['emails']} == {
        'work': 'leaver.new@example.com', 'home': 'lee@example.com'}
    # Unknown core attributes still fail explicitly, and nothing else in that PATCH applies.
    rejected = patch(client, path, [{'op': 'replace', 'path': 'active', 'value': True},
                                    {'op': 'replace', 'path': 'favoriteColor', 'value': 'blue'}])
    assert scim_type(rejected) == 'invalidPath' and client.get(path).json()['active'] is False
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': CORE + 'Group:displayName', 'value': 'x'}])) == 'invalidPath'
    assert scim_type(client.post('/scim/v2/Users', json={'userName': 'odd@example.com', 'favoriteColor': 'x'})) == 'invalidValue'
    assert scim_type(client.post('/scim/v2/Users', json={'schemas': ['other'], 'userName': 'odd@example.com'})) == 'invalidValue'


def test_attribute_names_are_case_insensitive(provision):
    """Regression: write paths compared attribute names exactly, contrary to RFC 7643 section 2.1."""
    client = provision.client
    person = user(client, 'case@example.com', DisplayName='Case', NAME={'GivenName': 'C'})
    assert person['displayName'] == 'Case' and person['name'] == {'givenName': 'C'}
    created = client.post('/scim/v2/Users', json={'Schemas': [(CORE + 'User').upper()], 'UserName': 'upper@example.com',
                                                   'Active': True, 'Emails': [{'Value': 'upper@example.com', 'Primary': True}]})
    assert created.status_code == 201, created.text
    assert created.json()['emails'] == [{'value': 'upper@example.com', 'primary': True}]
    path = '/scim/v2/Users/' + person['id']
    assert patch(client, path, [{'Op': 'replace', 'Path': 'Active', 'Value': False}]).json()['active'] is False
    assert patch(client, path, [{'op': 'replace', 'value': {'ACTIVE': True}}]).json()['active'] is True
    urn = (CORE + 'User:active').upper()
    assert patch(client, path, [{'op': 'replace', 'path': urn, 'value': False}]).json()['active'] is False
    assert patch(client, path, [{'op': 'replace', 'path': 'Name.FamilyName', 'value': 'Q'}]).json()['name'] == {
        'givenName': 'C', 'familyName': 'Q'}
    body = {'SCHEMAS': [PATCH], 'operations': [{'op': 'replace', 'path': 'displayName', 'value': 'Renamed'}]}
    assert client.patch(path, json=body).json()['displayName'] == 'Renamed'
    team = client.post('/scim/v2/Groups', json={'DISPLAYNAME': 'Case group', 'Members': [{'Value': person['id']}]})
    assert team.status_code == 201 and team.json()['members'][0]['value'] == person['id']
    duplicate = client.post('/scim/v2/Users', json={'userName': 'dup@example.com', 'USERNAME': 'other@example.com'})
    assert scim_type(duplicate) == 'invalidSyntax'


def test_patch_merges_complex_name_and_appends_emails(provision):
    client = provision.client
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
    assert patch(client, path, [{'op': 'replace', 'path': 'emails', 'value': [{'value': 'home@example.com'}]}]).json()[
        'emails'] == [{'value': 'home@example.com'}]
    assert scim_type(patch(client, path, [{'op': 'add', 'path': 'emails', 'value': {'value': 'other@example.com'}}])) == 'invalidValue'
    # Removing an absent attribute is idempotent.
    assert patch(client, path, [{'op': 'remove', 'path': 'title'}, {'op': 'remove', 'path': 'name.formatted'}]).status_code == 200


def test_remove_without_path_reports_no_target(provision):
    """Regression: RFC 7644 section 3.5.2.2 requires noTarget, not invalidPath."""
    client = provision.client
    path = '/scim/v2/Users/' + user(client)['id']
    assert scim_type(patch(client, path, [{'op': 'remove'}])) == 'noTarget'
    assert scim_type(patch(client, path, [{'op': 'remove', 'path': ''}])) == 'noTarget'
    assert scim_type(patch(client, path, [{'op': 'add', 'value': ['not', 'an', 'object']}])) == 'invalidValue'
    assert scim_type(patch(client, path, [{'op': 'remove', 'path': 'userName'}])) == 'mutability'


def test_entra_string_booleans_deactivate_only_through_patch(provision):
    client = provision.client
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    assert patch(client, path, [{'op': 'Replace', 'path': 'active', 'value': 'False'}]).json()['active'] is False
    assert not active(provision, person['userName'])
    assert patch(client, path, [{'op': 'replace', 'value': {'active': ' TRUE '}}]).json()['active'] is True
    assert active(provision, person['userName'])
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': 'active', 'value': 'no'}])) == 'invalidValue'
    assert client.put(path, json={'userName': person['userName'], 'active': 'false'}).status_code == 400


def test_member_limit_counts_distinct_submitted_references(provision, monkeypatch):
    """Regression: the cap counted existing and duplicate members, dropping removals bundled with additions."""
    monkeypatch.setattr(scim_module, 'MAX_MEMBERS', 5)
    client = provision.client
    people = [user(client, f'p{index}@example.com') for index in range(8)]
    team = group(client, people[:5])
    path = '/scim/v2/Groups/' + team['id']
    # A full group can lose one member and gain two in one atomic PATCH.
    changed = patch(client, path, [{'op': 'remove', 'path': f'members[value eq "{people[0]["id"]}"]'},
                                   {'op': 'add', 'path': 'members', 'value': [{'value': people[5]['id']}, {'value': people[6]['id']}]}])
    assert changed.status_code == 204, changed.text
    assert {item['value'] for item in client.get(path).json()['members']} == {person['id'] for person in people[1:7]}
    # Re-adding existing members (an IdP retry) and duplicates are one reference each.
    retried = patch(client, path, [{'op': 'add', 'path': 'members', 'value': [{'value': people[1]['id']}] * 9}])
    assert retried.status_code == 204 and len(client.get(path).json()['members']) == 6
    assert client.put(path, json={'displayName': 'Engineering',
                                  'members': [{'value': person['id']} for person in people[:5]] * 3}).status_code == 200
    too_many = [{'value': person['id']} for person in people[:6]]
    assert scim_type(client.put(path, json={'displayName': 'Engineering', 'members': too_many})) == 'invalidValue'
    assert scim_type(patch(client, path, [{'op': 'add', 'path': 'members', 'value': too_many[:3]},
                                          {'op': 'add', 'path': 'members', 'value': too_many[3:]}])) == 'invalidValue'
    assert len(client.get(path).json()['members']) == 5


def test_group_writes_change_only_the_membership_delta_in_batches(provision, monkeypatch):
    """Regression: every added member was a separate INSERT under the exclusive writer."""
    client, store = provision.client, provision.store
    stamp, ids = timestamp(), [f'{index:032x}' for index in range(1200)]
    with store.connect() as conn:
        conn.begin_write()
        conn.executemany('''INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision)
            VALUES(?,'',?,'{}',1,'',?,?,1)''', [(identity, identity + '@example.com', stamp, stamp) for identity in ids])
    executed = statements(monkeypatch)
    # More members than SQLite's historical 999 bound-variable limit.
    created = client.post('/scim/v2/Groups', json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[:1100]]})
    assert created.status_code == 201 and len(created.json()['members']) == 1100
    inserts = [statement for statement in executed if statement.startswith('INSERT INTO scim_group_members')]
    assert len(inserts) == 5, len(inserts)  # 250 rows per statement.
    path = '/scim/v2/Groups/' + created.json()['id']
    executed.clear()
    added = patch(client, path + '?excludedAttributes=members', [{'op': 'add', 'path': 'members', 'value': [{'value': ids[1100]}]}])
    assert added.status_code == 200 and 'members' not in added.json()
    assert len(executed) < 30, executed
    assert len(store.rows('SELECT user_id FROM scim_group_members')) == 1101
    failed = client.put(path, json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[600:] + ['missing']]})
    assert scim_type(failed) == 'invalidValue' and len(store.rows('SELECT user_id FROM scim_group_members')) == 1101
    replaced = client.put(path, json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[600:]]})
    assert replaced.status_code == 200 and {item['value'] for item in replaced.json()['members']} == set(ids[600:])
    assert {row['user_id'] for row in store.rows('SELECT user_id FROM scim_group_members')} == set(ids[600:])
    details = json.loads(scim_events(provision)[-1]['details'])
    assert details == {'token_id': provision.record['id'], 'members_added': 99, 'members_removed': 600}


def test_attribute_projection_matches_groups_without_loading_members(provision, monkeypatch):
    service, client = provision.service, provision.client
    person = user(client, name={'givenName': 'Pat'})
    team = group(client, [person], 'Eng')
    related, original = [], service._related_in
    monkeypatch.setattr(service, '_related_in', lambda *args: related.append(args[1]) or original(*args))
    found = client.get('/scim/v2/Groups', params={'excludedAttributes': 'members', 'filter': 'displayName eq "Eng"'})
    assert found.status_code == 200, found.text
    assert set(found.json()['Resources'][0]) == {'schemas', 'id', 'meta', 'displayName'} and related == []
    single = client.get('/scim/v2/Groups/' + team['id'], params={'excludedAttributes': CORE + 'Group:Members'}).json()
    assert single['displayName'] == 'Eng' and 'members' not in single
    users = client.get('/scim/v2/Users', params={'attributes': 'userName, NAME'}).json()['Resources']
    assert users[0] == {'schemas': [CORE + 'User'], 'id': person['id'], 'userName': person['userName'],
                        'name': {'givenName': 'Pat'}, 'meta': person['meta']}
    for params in ({'attributes': 'userName', 'excludedAttributes': 'name'}, {'attributes': 'password'},
                   {'excludedAttributes': 'name.givenName'}, {'attributes': ''}):
        for target in ('/scim/v2/Users', '/scim/v2/Users/' + person['id']):
            assert scim_type(client.get(target, params=params)) == 'invalidValue'


def test_handlers_query_the_database_off_the_event_loop(provision, monkeypatch):
    import asyncio
    service, client = provision.service, provision.client
    running, original = [], Scim._token_in

    def token_in(conn, header):
        try:
            running.append(bool(asyncio.get_running_loop()))
        except RuntimeError:
            running.append(False)
        return original(conn, header)

    monkeypatch.setattr(Scim, '_token_in', staticmethod(token_in))
    person = user(client)
    assert client.get('/scim/v2/Users/' + person['id']).status_code == 200
    assert client.get('/scim/v2/Users').status_code == 200
    assert client.get('/scim/v2/ServiceProviderConfig').status_code == 200
    assert patch(client, '/scim/v2/Users/' + person['id'], [{'op': 'replace', 'path': 'title', 'value': 'Lead'}]).status_code == 200
    assert client.delete('/scim/v2/Users/' + person['id']).status_code == 204
    assert len(running) >= 7 and not any(running)
    assert service.create_token  # Admin methods are synchronous; native routes call them in threads.


async def test_body_limit_stops_reading_declared_and_chunked_requests(provision):
    from starlette.requests import Request
    service, token = provision.service, provision.token
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
    with pytest.raises(ScimError) as error:
        await service.body(request())
    assert error.value.status == 413 and len(received) == 3


@pytest.mark.parametrize('content', [b'[' * 200000, b'[' * 100000 + b']' * 100000, b'{"a":' * 100000])
def test_deeply_nested_bodies_are_invalid_syntax(provision, content):
    """Regression: RecursionError escaped the SCIM error handling as a plain 500."""
    client = provision.client
    for method, path in (('POST', '/scim/v2/Users'), ('PATCH', '/scim/v2/Users/' + user(client, f'{len(content)}@example.com')['id'])):
        response = client.request(method, path, content=content, headers={'content-type': MEDIA})
        assert scim_type(response) == 'invalidSyntax'
    assert len(provision.store.rows("SELECT id FROM scim_users WHERE deleted_at=''")) == 1


def test_malformed_payloads_and_immutable_identity_do_not_partially_write(provision):
    client, store = provision.client, provision.store
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': 'userName', 'value': 'other@example.com'}])) == 'mutability'
    assert client.post('/scim/v2/Users', json={'userName': 'other@example.com', 'active': 'false'}).status_code == 400
    assert scim_type(client.post('/scim/v2/Users', content='{', headers={'content-type': MEDIA})) == 'invalidSyntax'
    assert scim_type(client.post('/scim/v2/Users', content='body', headers={'content-type': 'text/plain'}), 415) is None
    assert client.get('/scim/v2/Users', params={'sortBy': 'userName'}).status_code == 400
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': 'members[value eq "x"]', 'value': 1}])) == 'invalidPath'
    assert scim_type(client.patch(path, json={'Operations': []})) == 'invalidSyntax'
    assert len(store.rows("SELECT id FROM scim_users WHERE deleted_at=''")) == 1
    # Ignored attributes stay unstored on PUT too.
    put = client.put(path, json={'userName': person['userName'], 'password': 'hidden', 'roles': [{'value': 'admin'}]})
    assert put.status_code == 200 and 'hidden' not in json.dumps(store.rows('SELECT profile FROM scim_users'))


def test_deactivation_tombstone_and_reactivation(provision):
    client = provision.client
    person = user(client)
    path = '/scim/v2/Users/' + person['id']
    changed = patch(client, path, [{'op': 'replace', 'path': 'active', 'value': False},
                                   {'op': 'replace', 'path': 'name.givenName', 'value': 'Pat'}])
    assert changed.status_code == 200 and changed.json()['name']['givenName'] == 'Pat'
    assert not active(provision, person['userName'])
    assert patch(client, path, [{'op': 'replace', 'value': {'active': True}}]).status_code == 200
    assert active(provision, person['userName'])
    assert client.delete(path).status_code == 204 and client.get(path).status_code == 404
    assert client.get('/scim/v2/Users', params={'filter': 'userName eq "person@example.com"'}).json()['totalResults'] == 0
    assert not active(provision, person['userName'])
    replacement = user(client)
    assert replacement['id'] != person['id'] and active(provision, person['userName'])
    assert [row['action'] for row in scim_events(provision) if row['resource_type'] == 'scim_user'] == [
        'scim_user.created', 'scim_user.deactivated', 'scim_user.reactivated', 'scim_user.deleted', 'scim_user.created']
    assert {row['actor'] for row in scim_events(provision) if row['resource_type'] == 'scim_user'} == {'Directory provider'}


def test_last_active_administrator_cannot_be_deprovisioned(provision):
    client, store = provision.client, provision.store
    owner = user(client, 'owner@example.com')
    path = '/scim/v2/Users/' + owner['id']
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': 'active', 'value': False}]), 409) is None
    assert scim_type(client.delete(path), 409) is None
    assert scim_type(client.put(path, json={'userName': 'owner@example.com', 'active': False}), 409) is None
    assert client.get(path).json()['active']
    assert not store.rows("SELECT 1 FROM governance_audit_events WHERE action IN ('scim_user.deactivated','scim_user.deleted')")
    # Provisioning another person never counts as losing the last administrator.
    assert user(client, 'member@example.com', active=False)['active'] is False


@pytest.mark.parametrize('operation', ['patch', 'delete'])
def test_concurrent_deprovisioning_preserves_one_active_administrator(provision, operation):
    service, client, roles = provision.service, provision.client, provision.roles
    provision.settings.google_admin_emails = 'owner@example.com,second@example.com'
    people = [user(client, 'owner@example.com'), user(client, 'second@example.com')]
    barrier, header = Barrier(2), 'Bearer ' + provision.token

    def deprovision(person):
        barrier.wait(timeout=5)
        try:
            if operation == 'patch':
                service.write(header, {}, 'User', 'PATCH', {'schemas': [PATCH], 'Operations': [
                    {'op': 'replace', 'path': 'active', 'value': False}]}, person['id'])
            else:
                service.delete(header, 'User', person['id'])
            return 200
        except ScimError as error:
            return error.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(deprovision, people))
    assert sorted(outcomes) == [200, 409]
    with provision.store.connect() as conn:
        assert len(roles.admins_in(conn)) == 1


def test_revocation_between_parse_and_write_cannot_admit_a_mutation(provision, monkeypatch):
    service, client, store = provision.service, provision.client, provision.store
    original = service.body

    async def revoke_after_parse(request):
        document = await original(request)
        store.execute('UPDATE scim_tokens SET revoked_at=?', (timestamp(),))
        return document

    monkeypatch.setattr(service, 'body', revoke_after_parse)
    response = client.post('/scim/v2/Users', json={'userName': 'race@example.com'})
    assert scim_type(response, 401) is None
    assert not store.rows('SELECT id FROM scim_users')
    assert not store.rows("SELECT id FROM governance_audit_events WHERE resource_type='scim_user'")


def test_revocation_holding_the_writer_wins_over_a_waiting_write(provision):
    """A revoke committed while a provisioning write waits for the canonical writer stops that write."""
    service, store = provision.service, provision.store
    header, holding, release = 'Bearer ' + provision.token, threading.Event(), threading.Event()
    record = provision.record

    def revoke():
        with store.connect() as conn:
            conn.begin_write()
            conn.execute('UPDATE scim_tokens SET revoked_at=? WHERE id=?', (timestamp(), record['id']))
            holding.set()
            release.wait(timeout=5)

    def provision_user():
        holding.wait(timeout=5)
        try:
            service.write(header, {}, 'User', 'POST', {'userName': 'waiting@example.com'})
            return 201
        except ScimError as error:
            return error.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        revoker = pool.submit(revoke)
        writer = pool.submit(provision_user)
        holding.wait(timeout=5)
        threading.Timer(0.3, release.set).start()
        revoker.result(timeout=10)
        assert writer.result(timeout=20) == 401
    assert not store.rows("SELECT id FROM scim_users WHERE user_name='waiting@example.com'")


def test_database_pressure_is_a_retryable_scim_error(provision, monkeypatch):
    def busy(*args, **kwargs):
        raise DatabaseBusyError('Postgres is busy; the transaction was not acknowledged.')

    monkeypatch.setattr(provision.service, 'read', busy)
    response = provision.client.get('/scim/v2/Users')
    assert scim_type(response, 503) is None and response.headers['retry-after'] == '5'


def test_admin_directory_pages_users_with_counts_and_constant_statements(provision, monkeypatch):
    """Regression: the provisioning page read every user and group one by one, unpaged, on the loop."""
    service, client, roles = provision.service, provision.client, provision.roles
    people = [user(client, f'u{index:02}@example.com', displayName=f'User {index}') for index in range(5)]
    team = group(client, people[:3], 'Engineering')
    group(client, people[:1], 'alumni')
    patch(client, '/scim/v2/Users/' + people[2]['id'], [{'op': 'replace', 'path': 'active', 'value': False}])
    roles.enterprise.create(RoleCreate(id='reader', name='Reader', permissions=['workspace.read']), OWNER)
    roles.enterprise.set_group_role(team['id'], GroupRoleChange(role_id='reader'), OWNER)
    first = service.directory(limit=2, actor=OWNER)
    assert [item['user_name'] for item in first['users']['items']] == ['u00@example.com', 'u01@example.com']
    assert first['users']['items'][0] == {'id': people[0]['id'], 'user_name': 'u00@example.com', 'display_name': 'User 0',
                                          'active': True, 'external_id': '', 'groups_count': 2,
                                          'updated_at': people[0]['meta']['lastModified']}
    second = service.directory(first['users']['next_cursor'], 2, OWNER)
    third = service.directory(second['users']['next_cursor'], 2, OWNER)
    assert [item['user_name'] for item in second['users']['items'] + third['users']['items']] == [
        'u02@example.com', 'u03@example.com', 'u04@example.com']
    assert third['users']['next_cursor'] is None and second['users']['items'][0]['active'] is False
    # Load more keeps the first page's sections instead of re-aggregating every membership.
    assert (second['groups'], second['tokens'], second['activity']) == (None, None, None)
    assert [(row['display_name'], row['member_count'], row['role_id'], row['role_name']) for row in first['groups']] == [
        ('alumni', 1, None, None), ('Engineering', 2, 'reader', 'Reader')]
    assert first['base_url'] == 'http://localhost:8787/scim/v2'
    assert first['activity'][0]['action'] == 'scim_user.deactivated' and len(first['activity']) <= 20
    assert all(entry['source'] == 'governance' and isinstance(entry['details'], dict) for entry in first['activity'])
    for cursor in ('not-a-cursor', '', 'W10'):
        if cursor:
            with pytest.raises(GovernanceInvalid):
                service.directory(cursor, 2, OWNER)
    for limit in (0, 201):
        with pytest.raises(GovernanceInvalid):
            service.directory(None, limit, OWNER)
    executed = statements(monkeypatch)
    service.directory(limit=50, actor=OWNER)
    baseline = len(executed)
    for index in range(20):
        user(client, f'more{index:02}@example.com')
    group(client, people, 'Everyone')
    executed.clear()
    service.directory(limit=50, actor=OWNER)
    assert len(executed) == baseline


def test_group_grants_follow_live_membership(provision):
    client, roles = provision.client, provision.roles
    roles.enterprise.create(RoleCreate(id='connector', name='Connector', permissions=['connections.manage']), OWNER)
    person = user(client, 'maya@example.com')
    team = group(client, [person], 'Connectors')
    roles.enterprise.set_group_role(team['id'], GroupRoleChange(role_id='connector'), OWNER)
    assert roles.permissions('maya@example.com') == MEMBER_PERMISSIONS | {'connections.manage'}
    assert patch(client, '/scim/v2/Groups/' + team['id'], [{'op': 'remove', 'path': 'members'}]).status_code == 204
    assert roles.permissions('maya@example.com') == MEMBER_PERMISSIONS
    assert patch(client, '/scim/v2/Groups/' + team['id'], [{'op': 'add', 'path': 'members',
                                                            'value': [{'value': person['id']}]}]).status_code == 204
    assert client.delete('/scim/v2/Groups/' + team['id']).status_code == 204
    assert roles.permissions('maya@example.com') == MEMBER_PERMISSIONS


def hold_writer(store):
    """Hold the canonical exclusive writer from another connection; returns its release."""
    if store.database:
        import psycopg
        holder = psycopg.connect(os.environ['MOYAI_TEST_POSTGRES_URL'])
        holder.execute('SELECT pg_advisory_xact_lock(726941, %s::regnamespace::oid::int)', (store.database.schema,))
    else:
        holder = sqlite3.connect(store.path, isolation_level=None)
        holder.execute('BEGIN IMMEDIATE')

    def release():
        holder.rollback()
        holder.close()
    return release


def test_unauthenticated_requests_never_queue_for_the_writer(provision, monkeypatch):
    """Regression: DELETE requested the canonical exclusive writer before checking the bearer credential."""
    from app.database import PostgresConnection, SQLiteConnection
    client, service, store = provision.client, provision.service, provision.store
    person, writers, connections = user(client), [], []
    team = group(client, [person])
    for kind in (SQLiteConnection, PostgresConnection):
        monkeypatch.setattr(kind, 'begin_write', lambda self, original=kind.begin_write: writers.append(1) or original(self))
    connect = store.connect
    monkeypatch.setattr(store, 'connect', lambda **kwargs: connections.append(1) or connect(**kwargs))
    forged = 'Bearer moyai_scim_' + provision.record['id'] + '.' + 'A' * 43
    body = {'schemas': [CORE + 'User'], 'userName': person['userName'], 'active': False}
    operations = {'schemas': [PATCH], 'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]}
    for header in ('', 'Bearer garbage', 'Basic ' + provision.token, forged):
        headers = {'Authorization': header}
        for response in (client.delete('/scim/v2/Users/' + person['id'], headers=headers),
                         client.delete('/scim/v2/Groups/' + team['id'], headers=headers),
                         client.patch('/scim/v2/Users/' + person['id'], json=operations, headers=headers),
                         client.put('/scim/v2/Users/' + person['id'], json=body, headers=headers),
                         client.post('/scim/v2/Users', json={'userName': 'new@example.com'}, headers=headers),
                         client.get('/scim/v2/Users', headers=headers)):
            assert scim_type(response, 401) is None
        for call in (lambda header=header: service.delete(header, 'User', person['id']),
                     lambda header=header: service.write(header, {}, 'User', 'PATCH', operations, person['id']),
                     lambda header=header: service.write(header, {}, 'Group', 'PATCH', operations, team['id']),
                     lambda header=header: service.read(header, {}, 'User'),
                     lambda header=header: service.authenticate(header)):
            with pytest.raises(ScimError) as error:
                call()
            assert error.value.status == 401
        # A malformed header never takes a connection; a well-formed one reads, never writes.
        assert not connections if header != forged else connections
    assert not writers
    assert client.get('/scim/v2/Users/' + person['id']).json()['active'] is True
    assert len(client.get('/scim/v2/Groups/' + team['id']).json()['members']) == 1


def test_unauthenticated_delete_returns_while_another_writer_holds_the_lock(provision):
    client = provision.client
    person = user(client)
    forged = 'Bearer moyai_scim_' + provision.record['id'] + '.' + 'A' * 43
    release = hold_writer(provision.store)
    try:
        for header in ('Bearer garbage', forged):
            started = time.monotonic()
            response = client.delete('/scim/v2/Users/' + person['id'], headers={'Authorization': header})
            assert scim_type(response, 401) is None and time.monotonic() - started < 3
    finally:
        release()
    assert client.delete('/scim/v2/Users/' + person['id']).status_code == 204


def test_token_use_bookkeeping_never_fails_or_stalls_a_request(provision, monkeypatch):
    """Regression: the throttled last_used_at write waited for the writer and turned finished reads into 503s."""
    client, store = provision.client, provision.store
    user(client)
    stale = '2020-01-01T00:00:00.000000+00:00'
    store.execute('UPDATE scim_tokens SET last_used_at=?', (stale,))
    release = hold_writer(store)
    try:
        started = time.monotonic()
        found = client.get('/scim/v2/Users', params={'filter': 'userName eq "person@example.com"'})
        assert found.status_code == 200 and found.json()['totalResults'] == 1
        assert client.get('/scim/v2/ServiceProviderConfig').status_code == 200
        assert time.monotonic() - started < 5
    finally:
        release()
    assert store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at'] == stale  # Skipped, not failed.
    connect = store.connect

    def busy(**kwargs):
        if kwargs.get('write_scope') == 'scim-token-use':
            raise DatabaseBusyError('Postgres is busy; the transaction was not acknowledged.')
        return connect(**kwargs)

    monkeypatch.setattr(store, 'connect', busy)
    assert client.get('/scim/v2/Users').status_code == 200
    monkeypatch.setattr(store, 'connect', connect)
    assert client.get('/scim/v2/Users').status_code == 200
    assert store.rows('SELECT last_used_at FROM scim_tokens')[0]['last_used_at'] > stale


def test_a_rename_never_voids_deprovisioning(provision):
    """Regression: a userName change bundled with active=false (Entra after a UPN change) rejected the
    whole write, so the deactivation was lost on every retry."""
    client = provision.client
    person = user(client, name={'givenName': 'Jo'})
    path = '/scim/v2/Users/' + person['id']
    renamed = 'zz_jdoe@example.com'
    response = patch(client, path, [{'op': 'Replace', 'path': 'userName', 'value': renamed},
                                    {'op': 'Replace', 'path': 'active', 'value': 'False'}])
    assert response.status_code == 200, response.text
    assert response.json()['userName'] == 'person@example.com' and response.json()['active'] is False
    assert not active(provision, 'person@example.com')
    # Later exports keep sending the rename; an inactive result applies under the stored userName.
    updated = patch(client, path, [{'op': 'replace', 'value': {'userName': renamed, 'displayName': 'Jo Doe'}}])
    assert updated.status_code == 200 and updated.json()['displayName'] == 'Jo Doe'
    replaced = client.put(path, json={'userName': renamed, 'active': False})
    assert replaced.status_code == 200 and replaced.json()['userName'] == 'person@example.com'
    # Reactivating under another userName still fails closed and changes nothing.
    assert scim_type(patch(client, path, [{'op': 'replace', 'path': 'userName', 'value': renamed},
                                          {'op': 'replace', 'path': 'active', 'value': True}])) == 'mutability'
    assert scim_type(client.put(path, json={'userName': renamed, 'active': True})) == 'mutability'
    assert not active(provision, 'person@example.com')
    assert client.get('/scim/v2/Users', params={'filter': f'userName eq "{renamed}"'}).json()['totalResults'] == 0
    # A PUT deactivation of an active user with a new userName is kept too.
    other = user(client, 'other@example.com')
    assert client.put('/scim/v2/Users/' + other['id'], json={'userName': 'zz_other@example.com', 'active': False}).json()[
        'userName'] == 'other@example.com'
    assert not active(provision, 'other@example.com')
    events = [row for row in scim_events(provision) if row['resource_type'] == 'scim_user']
    assert [row['action'] for row in events] == ['scim_user.created', 'scim_user.deactivated', 'scim_user.updated',
                                                 'scim_user.updated', 'scim_user.created', 'scim_user.deactivated']
    assert [json.loads(row['details']) for row in events[1:4]] == [
        {'token_id': provision.record['id'], 'active': False, 'rename_ignored': True}] * 3
    assert 'zz_' not in json.dumps(events)


def test_group_patch_work_and_response_follow_the_request_not_the_group(provision, monkeypatch):
    """Regression: every Group PATCH loaded, copied and revalidated all members under the exclusive
    writer, then returned them; list pages materialized every member of every group."""
    from app.database import PostgresConnection, SQLiteConnection
    client, service, store = provision.client, provision.service, provision.store
    stamp, ids = timestamp(), [f'{index:032x}' for index in range(1200)]
    with store.connect() as conn:
        conn.begin_write()
        conn.executemany('''INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision)
            VALUES(?,'',?,'{}',1,'',?,?,1)''', [(identity, identity + '@example.com', stamp, stamp) for identity in ids])
    team = client.post('/scim/v2/Groups', json={'displayName': 'Everyone', 'members': [{'value': value} for value in ids[:1100]]})
    assert team.status_code == 201
    path = '/scim/v2/Groups/' + team.json()['id']
    validated, loaded, writers = [], [], []
    for kind in (SQLiteConnection, PostgresConnection):
        def begin_write(self, original=kind.begin_write):
            self.wrote = True
            writers.append(1)
            return original(self)
        monkeypatch.setattr(kind, 'begin_write', begin_write)
    member_ids, resource_in = scim_module.member_ids, service.resource_in
    monkeypatch.setattr(scim_module, 'member_ids', lambda members, *args: validated.extend(members) or member_ids(members, *args))
    monkeypatch.setattr(service, 'resource_in', lambda conn, kind, identity, related=True: loaded.append(
        (kind, related, getattr(conn, 'wrote', False))) or resource_in(conn, kind, identity, related=related))
    executed = statements(monkeypatch)
    added = patch(client, path, [{'op': 'add', 'path': 'members', 'value': [{'value': ids[1100]}]},
                                 {'op': 'remove', 'path': f'members[value eq "{ids[0]}"]'},
                                 {'op': 'replace', 'path': 'displayName', 'value': 'All staff'}])
    assert added.status_code == 204 and not added.content
    # Only the submitted reference is validated; stored members are looked up by id, never listed.
    assert validated == [{'value': ids[1100]}] and loaded == [('Group', False, True)]
    reads = [statement for statement in executed if 'FROM scim_group_members' in statement and 'SELECT' in statement]
    assert reads and all('user_id=?' in statement or 'IN (' in statement for statement in reads), reads
    current = client.get(path).json()
    assert current['displayName'] == 'All staff' and len(current['members']) == 1100
    assert {item['value'] for item in current['members']} == set(ids[1:1101])
    # A requested representation is read after commit, outside the writer.
    loaded.clear()
    shown = patch(client, path + '?attributes=members', [{'op': 'remove', 'path': 'members',
                                                           'value': [{'value': ids[1]}]}])
    assert shown.status_code == 200 and len(shown.json()['members']) == 1099 and loaded[-1] == ('Group', True, False)
    hidden = patch(client, path + '?excludedAttributes=members', [{'op': 'add', 'path': 'members', 'value': [{'value': ids[1]}]}])
    assert hidden.status_code == 200 and 'members' not in hidden.json() and hidden.json()['displayName'] == 'All staff'
    # Group pages include members only on request; a single group still returns them.
    listed = client.get('/scim/v2/Groups').json()['Resources']
    assert len(listed) == 1 and 'members' not in listed[0] and listed[0]['displayName'] == 'All staff'
    assert len(client.get('/scim/v2/Groups', params={'attributes': 'members'}).json()['Resources'][0]['members']) == 1100
    assert len(client.get(path).json()['members']) == 1100
    assert json.loads(scim_events(provision)[-1]['details'])['members_added'] == 1


def test_responses_render_off_the_event_loop(provision, monkeypatch):
    import asyncio
    client, rendered = provision.client, []
    original = scim_module.render

    def render(content):
        try:
            rendered.append(bool(asyncio.get_running_loop()))
        except RuntimeError:
            rendered.append(False)
        return original(content)

    monkeypatch.setattr(scim_module, 'render', render)
    person = user(client)
    assert client.get('/scim/v2/Users').status_code == 200 and client.get('/scim/v2/Users/' + person['id']).status_code == 200
    assert patch(client, '/scim/v2/Users/' + person['id'], [{'op': 'replace', 'path': 'title', 'value': 'x'}]).status_code == 200
    assert len(rendered) == 4 and not any(rendered)


def test_unencodable_text_and_nul_are_permanent_client_errors(provision, monkeypatch):
    """Regression: escaped lone surrogates escaped as plain 500s (after a committed write for profile
    fields) and NUL in ids or filters became a retryable 503 on PostgreSQL."""
    client, service = provision.client, provision.service
    person = user(client)
    team = group(client, [person])

    def raw(method, path, content):
        return client.request(method, path, content=content, headers={'content-type': MEDIA})

    for method, path, content in (
            ('POST', '/scim/v2/Groups', b'{"displayName":"\\ud800"}'),
            ('POST', '/scim/v2/Groups', b'{"displayName":"Ops","externalId":"\\udfff"}'),
            ('POST', '/scim/v2/Users', b'{"userName":"new@example.com","externalId":"\\ud800"}'),
            ('POST', '/scim/v2/Users', b'{"userName":"new@example.com","displayName":"a\\ud800b"}'),
            ('POST', '/scim/v2/Users', b'{"userName":"new@example.com","name":{"givenName":"\\u0000"}}'),
            ('PATCH', '/scim/v2/Users/' + person['id'],
             b'{"schemas":["' + PATCH.encode() + b'"],"Operations":[{"op":"replace","path":"title","value":"\\ud800"}]}'),
            ('PATCH', '/scim/v2/Groups/' + team['id'],
             b'{"schemas":["' + PATCH.encode() + b'"],"Operations":[{"op":"add","path":"members","value":[{"value":"\\u0000"}]}]}')):
        assert scim_type(raw(method, path, content)) == 'invalidValue', (method, path, content)
    for operation in ('members[value eq "\\u0000"]', 'members[value eq "\\ud800"]'):
        assert scim_type(patch(client, '/scim/v2/Groups/' + team['id'], [{'op': 'remove', 'path': operation}])) == 'invalidPath'
    for expression in ('externalId eq "\\ud800"', 'userName eq "a\\u0000"', 'id eq "\\u0000"'):
        assert scim_type(client.get('/scim/v2/Users', params={'filter': expression})) == 'invalidFilter'
    assert scim_type(client.get('/scim/v2/Groups', params={'filter': 'displayName eq "\\ud800"'})) == 'invalidFilter'
    for method in ('GET', 'PUT', 'PATCH', 'DELETE'):
        for collection in ('Users', 'Groups'):
            response = client.request(method, f'/scim/v2/{collection}/%00', json={'schemas': [PATCH], 'Operations': [
                {'op': 'replace', 'path': 'displayName', 'value': 'x'}]} if method != 'GET' else None)
            assert scim_type(response, 404) is None, (method, collection, response.text)
    # Nothing was written, and the directory stays readable.
    listing = client.get('/scim/v2/Users')
    assert listing.status_code == 200 and listing.json()['totalResults'] == 1
    assert client.get('/scim/v2/Groups/' + team['id']).json()['displayName'] == 'Engineering'
    with pytest.raises(GovernanceInvalid):
        service.directory(scim_module._cursor(['\x00', 'a']), 2, OWNER)
    # Anything unencodable that slips through is still a SCIM 400, never a plain 500.
    monkeypatch.setattr(service, 'read', lambda *args: (_ for _ in ()).throw(
        UnicodeEncodeError('utf-8', '\ud800', 0, 1, 'surrogates not allowed')))
    assert scim_type(client.get('/scim/v2/Users')) == 'invalidValue'


def test_list_pages_read_resources_and_memberships_in_constant_statements(provision, monkeypatch):
    """Regression: each listed resource was read, with its groups or members, by its own queries."""
    client = provision.client
    pair = [user(client, f'pair{index}@example.com') for index in range(2)]
    group(client, pair, 'Pair')
    executed = statements(monkeypatch)

    def page(kind, **params):
        executed.clear()
        response = client.get('/scim/v2/' + kind, params=params)
        assert response.status_code == 200, response.text
        return len(executed), response.json()['Resources']

    small = page('Users')[0], page('Groups', attributes='displayName,members')[0]
    more = [user(client, f'more{index}@example.com') for index in range(6)]
    group(client, more, 'More')
    group(client, [*pair, *more], 'Everyone')
    (users_run, users), (groups_run, groups) = page('Users'), page('Groups', attributes='displayName,members')
    assert (users_run, groups_run) == small and [len(item['groups']) for item in users] == [2] * 8
    assert sorted((item['displayName'], len(item['members'])) for item in groups) == [
        ('Everyone', 8), ('More', 6), ('Pair', 2)]
    # A page holds the same documents as reading each resource on its own.
    assert users == [client.get('/scim/v2/Users/' + item['id']).json() for item in users]
    assert groups == [client.get('/scim/v2/Groups/' + item['id']).json() for item in groups]
