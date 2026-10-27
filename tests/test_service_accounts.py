"""Service accounts and API keys on the real transactional database (SQLite or --postgres-backend)."""
import hashlib
import json
import re
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from app import scim
from app import service_accounts as module
from app.config import Settings
from app.database import DatabaseBusyError
from app.db import Store
from app.enterprise_roles import (
    GovernanceActor,
    GovernanceConflict,
    GovernanceForbidden,
    GovernanceNotFound,
    RoleAssignment,
    RoleCreate,
)
from app.governance_audit import GovernanceAudit, parse_filters
from app.permissions import (
    API_KEY_ROUTES,
    MEMBER_PERMISSIONS,
    PERMISSIONS,
    SERVICE_PERMISSIONS,
    api_key_route,
    route_permission,
)
from app.service_accounts import (
    MAX_ACTIVE_KEYS,
    ServiceAccountCreate,
    ServiceAccounts,
    ServiceAccountUpdate,
    ServiceKeyCreate,
    is_principal_id,
    key_row_in,
    logged_prefix,
    parse,
    presented,
    verify,
)
from app.user_roles import UserRoles
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from test_scim import hold_writer

OWNER = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin', kind='individual')
STEWARD = GovernanceActor(id='google:maya', email='maya@example.com', kind='individual')
PLAIN = GovernanceActor(id='google:plain', email='plain@example.com', kind='individual')


@pytest.fixture
def accounts(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    store = Store(tmp_path)
    try:
        roles = UserRoles(store, settings)
        yield SimpleNamespace(service=ServiceAccounts(store, roles), store=store, roles=roles, settings=settings)
    finally:
        store.close()


def siem(service, **body):
    return service.create(ServiceAccountCreate(**{'name': 'SIEM collector', 'permissions': ['audit.read'], **body}),
                          OWNER)


def update(account, **changes):
    body = {key: account[key] for key in ('name', 'description', 'permissions', 'active', 'revision')}
    return ServiceAccountUpdate(**{**body, **changes})


def events(store):
    return [dict(row) for row in store.rows('''SELECT action,actor,resource_type,resource_id,details
        FROM governance_audit_events WHERE resource_type IN ('service_account','service_account_key')
        ORDER BY created_at,id''')]


def verified(store, key_id, token=None, **kwargs):
    with store.connect() as conn:
        return verify(key_row_in(conn, key_id), token, **kwargs)


def access_revision(store, account_id):
    return store.rows('SELECT access_revision FROM service_accounts WHERE id=?', (account_id,))[0]['access_revision']


def test_keys_are_shown_once_stored_as_hashes_and_every_change_records_one_event(accounts):
    service, store = accounts.service, accounts.store
    account = siem(service, description='Splunk pulls the audit export.')
    assert (account['permissions'], account['revision'], account['active'], account['keys']) == (['audit.read'], 1, True, [])
    record, token = service.create_key(account['id'], ServiceKeyCreate(label='Splunk', expires_in_days=30), OWNER)
    assert re.fullmatch(r'moyai_sk_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}', token)
    assert record['prefix'] == token[:17] and re.fullmatch(r'moyai_sk_[0-9a-f]{8}', record['prefix'])
    assert record['status'] == 'active' and 'token' not in record and 'token_hash' not in record
    expires = datetime.fromisoformat(record['expires_at']) - datetime.fromisoformat(record['created_at'])
    assert expires == timedelta(days=30)
    secret = token.partition('.')[2]
    saved = [dict(row) for table in ('service_accounts', 'service_account_keys') for row in store.rows(f'SELECT * FROM {table}')]
    assert saved[1]['token_hash'] == hashlib.sha256(token.encode()).hexdigest()
    assert not any(token in str(value) or secret in str(value) for row in saved for value in row.values())
    service.revoke_key(account['id'], record['id'], OWNER)
    renamed = service.update(account['id'], update(account, name='SIEM'), OWNER)
    service.disable(account['id'], renamed['revision'], OWNER)
    recorded = events(store)
    assert [row['action'] for row in recorded] == [
        'service_account.created', 'service_account_key.created', 'service_account_key.revoked',
        'service_account.updated', 'service_account.disabled']
    assert {row['actor'] for row in recorded} == {'owner@example.com'}
    text = json.dumps(recorded)
    assert token not in text and secret not in text and saved[1]['token_hash'] not in text
    assert all(len(row['details'].encode()) < 512 for row in recorded)
    assert json.loads(recorded[1]['details']) == {'account_id': account['id'], 'label': 'Splunk',
                                                  'prefix': record['prefix'], 'expires_at': record['expires_at']}
    listing = service.listing(OWNER)
    assert token not in json.dumps(listing) and saved[1]['token_hash'] not in json.dumps(listing)


def test_a_rolled_back_change_leaves_no_event(accounts, monkeypatch):
    service, store = accounts.service, accounts.store

    def fail(conn, account_id):
        raise RuntimeError('after the event')
    monkeypatch.setattr(service, '_view_in', fail)
    with pytest.raises(RuntimeError):
        siem(service)
    assert store.rows('SELECT * FROM service_accounts') == [] and events(store) == []


def test_only_builtin_administrators_widen_access_and_holders_only_narrow_it(accounts):
    service, roles = accounts.service, accounts.roles
    roles.enterprise.create(RoleCreate(id='key-steward', name='Key steward',
                                       permissions=['service_accounts.manage', 'audit.read']), OWNER)
    roles.enterprise.assign(RoleAssignment(email='maya@example.com', role_id='key-steward'), OWNER)
    account = siem(service)
    record, _ = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    second, _ = service.create_key(account['id'], ServiceKeyCreate(label='Backup'), OWNER)
    # Holding audit.read and service_accounts.manage still issues and widens nothing.
    for actor in (STEWARD, PLAIN):
        for attempt, *arguments in (
                (service.create, ServiceAccountCreate(name='Mine', permissions=['audit.read'])),
                (service.update, account['id'], update(account, permissions=['audit.read', 'spend.read'])),
                (service.update, account['id'], update(account, name='Renamed')),
                (service.create_key, account['id'], ServiceKeyCreate(label='Mine'))):
            with pytest.raises(GovernanceForbidden, match='built-in administrator'):
                attempt(*arguments, actor)
    listing = service.listing(STEWARD)
    assert listing['can_create'] is False and service.listing(OWNER)['can_create'] is True
    assert service.revoke_key(account['id'], record['id'], STEWARD)['revoked_by'] == 'maya@example.com'
    disabled = service.disable(account['id'], account['revision'], STEWARD)
    assert disabled['active'] is False and [key['status'] for key in disabled['keys']] == ['revoked', 'revoked']
    with pytest.raises(GovernanceForbidden):
        service.update(account['id'], update(disabled, active=True), STEWARD)
    for attempt in (lambda: service.listing(PLAIN), lambda: service.revoke_key(account['id'], second['id'], PLAIN),
                    lambda: service.disable(account['id'], disabled['revision'], PLAIN)):
        with pytest.raises(GovernanceForbidden):
            attempt()
    assert [row['actor'] for row in events(accounts.store)][-2:] == ['maya@example.com', 'maya@example.com']


def test_permissions_stay_inside_the_ceiling_and_keys_must_expire(accounts):
    service, store = accounts.service, accounts.store
    for permissions in (['sessions.create'], ['roles.manage'], ['audit.read', 'service_accounts.manage'], []):
        with pytest.raises(RequestValidationError):
            service.create({'name': 'Wide', 'permissions': permissions}, OWNER)
    for body in ({'name': 'x', 'permissions': ['audit.read']}, {'name': 'Nul\x00', 'permissions': ['audit.read']},
                 {'name': 'Extra', 'permissions': ['audit.read'], 'role': 'admin'}):
        with pytest.raises(RequestValidationError):
            service.create(body, OWNER)
    account = siem(service)
    for days in (0, 7, 366, None, '90'):
        with pytest.raises(RequestValidationError):
            service.create_key(account['id'], {'label': 'Bad', 'expires_in_days': days}, OWNER)
    assert service.create_key(account['id'], {'label': 'Default'}, OWNER)[0]['status'] == 'active'
    for index in range(4):
        service.create_key(account['id'], ServiceKeyCreate(label=f'Key {index}', expires_in_days=365), OWNER)
    with pytest.raises(GovernanceConflict, match='at most 5 active keys'):
        service.create_key(account['id'], ServiceKeyCreate(label='Sixth'), OWNER)
    # Expired keys no longer count toward the limit.
    store.execute("UPDATE service_account_keys SET expires_at='2020-01-01T00:00:00.000000+00:00' WHERE label='Key 0'")
    assert service.create_key(account['id'], ServiceKeyCreate(label='Sixth'), OWNER)[0]['status'] == 'active'
    with pytest.raises(GovernanceNotFound):
        service.create_key('0' * 32, ServiceKeyCreate(label='Missing'), OWNER)
    with pytest.raises(GovernanceConflict, match='already exists'):
        siem(service, name='siem COLLECTOR')


def test_revisions_conflict_revocation_is_idempotent_and_disable_is_permanent_for_keys(accounts):
    service, store = accounts.service, accounts.store
    account = siem(service)
    first, token = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    second, other = service.create_key(account['id'], ServiceKeyCreate(label='Backup'), OWNER)
    revoked = service.revoke_key(account['id'], first['id'], OWNER)
    assert revoked['status'] == 'revoked' and revoked['revoked_by'] == 'owner@example.com'
    assert service.revoke_key(account['id'], first['id'], OWNER) == revoked
    with pytest.raises(GovernanceNotFound):
        service.revoke_key('0' * 32, second['id'], OWNER)
    with pytest.raises(GovernanceConflict, match='changed elsewhere'):
        service.update(account['id'], update(account, revision=2), OWNER)
    changed = service.update(account['id'], update(account, description='Nightly export'), OWNER)
    with pytest.raises(GovernanceConflict, match='changed elsewhere'):
        service.disable(account['id'], account['revision'], OWNER)
    disabled = service.disable(account['id'], changed['revision'], OWNER)
    assert service.disable(account['id'], disabled['revision'], OWNER) == disabled  # A no-op, no event.
    assert {key['id']: key['revoked_by'] for key in disabled['keys']} == {
        first['id']: 'owner@example.com', second['id']: 'service_account.disabled'}
    assert json.loads(events(store)[-1]['details']) == {'name': 'SIEM collector', 'revoked_keys': [second['prefix']],
                                                        'revoked_count': 1}
    with pytest.raises(GovernanceConflict, match='Enable this service account'):
        service.create_key(account['id'], ServiceKeyCreate(label='Late'), OWNER)
    enabled = service.update(account['id'], update(disabled, active=True), OWNER)
    assert enabled['active'] is True and {key['status'] for key in enabled['keys']} == {'revoked'}
    assert verified(store, first['id'], token) is None and verified(store, second['id'], other) is None
    assert [row['action'] for row in events(store)][-3:] == [
        'service_account.updated', 'service_account.disabled', 'service_account.enabled']
    assert json.loads(events(store)[-1]['details']) == {'name': 'SIEM collector'}


def test_deactivating_through_an_update_revokes_keys_in_one_event_shaped_like_disable(accounts):
    service, store = accounts.service, accounts.store
    account = siem(service)
    record, token = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    disabled = service.update(account['id'], update(account, active=False, name='Retired SIEM'), OWNER)
    assert disabled['keys'][0]['revoked_by'] == 'service_account.disabled'
    last = events(store)[-1]
    assert last['action'] == 'service_account.disabled' and json.loads(last['details']) == {
        'name': 'Retired SIEM', 'revoked_keys': [record['prefix']], 'revoked_count': 1}
    assert verified(store, record['id'], token) is None
    # Permission fields appear only when the same edit changed them.
    enabled = service.update(account['id'], update(disabled, active=True, permissions=['spend.read']), OWNER)
    assert json.loads(events(store)[-1]['details']) == {
        'name': 'Retired SIEM', 'permissions': ['spend.read'], 'previous_permissions': ['audit.read']}
    second, _ = service.create_key(account['id'], ServiceKeyCreate(label='Second'), OWNER)
    service.update(account['id'], update(enabled, active=False, permissions=['audit.read']), OWNER)
    assert json.loads(events(store)[-1]['details']) == {
        'name': 'Retired SIEM', 'permissions': ['audit.read'], 'previous_permissions': ['spend.read'],
        'revoked_keys': [second['prefix']], 'revoked_count': 1}


@pytest.mark.parametrize('through', ['disable', 'update'])
def test_disabling_stays_within_the_event_bound_however_many_keys_expired_unrevoked(accounts, through):
    service, store = accounts.service, accounts.store
    account = siem(service)
    live = [service.create_key(account['id'], ServiceKeyCreate(label=f'Live {index}'), OWNER)[0]
            for index in range(MAX_ACTIVE_KEYS)]
    # Years of 30-day rotation without revoking: each expired key is still unrevoked.
    for index in range(250):
        identity = f'{index:032x}'
        store.execute('''INSERT INTO service_account_keys(id,account_id,label,token_hash,prefix,created_by,created_at,
            expires_at,last_used_at,last_used_from,revoked_at,revoked_by) VALUES(?,?,?,?,?,?,?,?,'','','','')''',
                      (identity, account['id'], f'Old {index}', f'{index:064x}', 'moyai_sk_' + identity[:8],
                       'owner@example.com', '2020-01-01T00:00:00.000000+00:00', '2020-01-31T00:00:00.000000+00:00'))
    if through == 'disable':
        disabled = service.disable(account['id'], account['revision'], OWNER)
    else:
        disabled = service.update(account['id'], update(account, active=False), OWNER)
    assert {key['status'] for key in disabled['keys']} == {'revoked'} and len(disabled['keys']) == 255
    last = events(store)[-1]
    assert last['action'] == 'service_account.disabled' and json.loads(last['details']) == {
        'name': 'SIEM collector', 'revoked_keys': [key['prefix'] for key in live], 'revoked_count': 255}


def test_only_active_accounts_count_toward_the_workspace_limit(accounts, monkeypatch):
    service = accounts.service
    monkeypatch.setattr(module, 'MAX_ACCOUNTS', 2)
    first, _ = siem(service, name='First'), siem(service, name='Second')
    with pytest.raises(GovernanceConflict, match='at most 2 active service accounts'):
        siem(service, name='Third')
    retired = service.disable(first['id'], first['revision'], OWNER)
    third = siem(service, name='Third')
    # Enabling needs a free place too, and a refused enable changes nothing.
    with pytest.raises(GovernanceConflict, match='at most 2 active'):
        service.update(first['id'], update(retired, active=True), OWNER)
    assert [account['active'] for account in service.listing(OWNER)['accounts']] == [False, True, True]
    service.disable(third['id'], third['revision'], OWNER)
    assert service.update(first['id'], update(retired, active=True), OWNER)['active'] is True


def test_access_revision_only_increases_across_narrowing_widening_and_state(accounts):
    service, store = accounts.service, accounts.store
    account = siem(service, permissions=['audit.read', 'spend.read'])
    seen = [access_revision(store, account['id'])]
    for changes in ({'permissions': ['audit.read']}, {'permissions': ['audit.read', 'spend.read']},
                    {'active': False}, {'active': True}):
        account = service.update(account['id'], update(account, **changes), OWNER)
        seen.append(access_revision(store, account['id']))
    assert seen == sorted(set(seen)) and len(seen) == 5
    renamed = service.update(account['id'], update(account, name='Renamed', description='Only metadata'), OWNER)
    assert access_revision(store, account['id']) == seen[-1] and renamed['revision'] == account['revision'] + 1
    unchanged = len(events(store))
    assert service.update(account['id'], update(renamed), OWNER) == renamed and len(events(store)) == unchanged


def test_verification_fails_closed_and_compares_hashes_in_constant_time(accounts, monkeypatch):
    service, store = accounts.service, accounts.store
    account = siem(service, permissions=['audit.read', 'spend.read'])
    record, token = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    compared = []
    original = module.hmac.compare_digest
    monkeypatch.setattr(module.hmac, 'compare_digest', lambda a, b: compared.append((a, b)) or original(a, b))
    authority = verified(store, record['id'], token)
    assert compared == [(hashlib.sha256(token.encode()).hexdigest(),) * 2]
    assert authority.permissions == frozenset({'audit.read', 'spend.read'}) and authority.account == account['id']
    assert authority.principal_id == f"service:{account['id']}:{record['id']}"
    entry = authority.authority_entry()
    assert entry['kind'] == 'service' and entry['permissions'] == ['audit.read', 'spend.read'] and token not in json.dumps(entry)
    wrong = token[:-1] + ('A' if token[-1] != 'A' else 'B')
    assert verified(store, record['id'], wrong) is None
    assert verified(store, record['id'], account_id=account['id']) is not None
    assert verified(store, record['id'], account_id='0' * 32) is None
    assert verified(store, '0' * 32, token) is None
    assert verified(store, record['id'], token, now=datetime.fromisoformat(record['expires_at'])) is None
    # Stored values outside the ceiling or catalog grant nothing; malformed lists grant nothing.
    store.execute('UPDATE service_accounts SET permissions=?', (json.dumps(['audit.read', 'roles.manage', 'x']),))
    assert verified(store, record['id'], token).permissions == frozenset({'audit.read'})
    store.execute("UPDATE service_accounts SET permissions='not json'")
    assert verified(store, record['id'], token).permissions == frozenset()
    store.execute("UPDATE service_account_keys SET expires_at='never'")
    assert verified(store, record['id'], token) is None
    store.execute("UPDATE service_account_keys SET expires_at=?", (record['expires_at'],))
    store.execute('UPDATE service_accounts SET active=0')
    assert verified(store, record['id'], token) is None
    # A check needs exactly one of the presented key and the grant's account; neither would accept any live row.
    store.execute('UPDATE service_accounts SET active=1')
    with store.connect() as conn:
        row = key_row_in(conn, record['id'])
    for kwargs in ({}, {'token': token, 'account_id': account['id']}):
        with pytest.raises(TypeError, match='exactly one'):
            verify(row, **kwargs)


def test_bearer_parsing_needs_no_database_and_never_accepts_other_credentials():
    _, token, _ = module.mint()
    assert parse('Bearer ' + token) == (token[9:41], token)
    assert parse('bearer\t' + token) == (token[9:41], token)
    for header in (None, '', token, 'Basic ' + token, 'Bearer ' + token + ' ', 'Bearer ' + token[:-1],
                   'Bearer ' + token.upper(), 'Bearer moyai_scim_' + token[9:], 'Bearer ' + token + '.x'):
        with pytest.raises(HTTPException) as refused:
            parse(header)
        assert refused.value.status_code == 401 and refused.value.headers == {'WWW-Authenticate': 'Bearer'}
    assert presented('Bearer ' + token) and presented('Token MOYAI_SK_x') and presented('bearer moyai_sk_')
    assert not presented(None) and not presented('Bearer moyai_scim_' + token[9:]) and not presented('')
    # Logs carry only a well-formed key's prefix, never any other part of a header.
    assert logged_prefix('Bearer ' + token) == token[:17]
    for header in (None, token, 'Bearer ' + token[:-1], 'Bearer ' + token + ' x', 'Bearer moyai_sk_' + 'g' * 32):
        assert logged_prefix(header) == ''
    assert is_principal_id('service:a:b') and not is_principal_id('google:service:a') and not is_principal_id(None)


def test_key_use_is_recorded_at_most_once_per_interval_and_never_for_revoked_keys(accounts, monkeypatch):
    service, store = accounts.service, accounts.store
    assert scim.TOKEN_USE_INTERVAL == timedelta(minutes=5)  # Shared with SCIM tokens.
    account = siem(service)
    record, _ = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    service.touch(record['id'], '', '203.0.113.7')
    first = store.rows('SELECT last_used_at,last_used_from FROM service_account_keys')[0]
    assert first['last_used_at'] and first['last_used_from'] == '203.0.113.7'
    service.touch(record['id'], first['last_used_at'], '198.51.100.1')
    # A caller that read an older value still cannot write twice in one interval.
    service.touch(record['id'], '', '198.51.100.1')
    assert store.rows('SELECT last_used_at,last_used_from FROM service_account_keys')[0] == first
    monkeypatch.setattr(scim, 'TOKEN_USE_INTERVAL', timedelta(0))
    service.revoke_key(account['id'], record['id'], OWNER)
    service.touch(record['id'], '', '198.51.100.1')
    assert store.rows('SELECT last_used_from FROM service_account_keys')[0]['last_used_from'] == '203.0.113.7'
    listed = service.listing(OWNER)['accounts'][0]['keys'][0]
    assert (listed['last_used_at'], listed['last_used_from']) == (first['last_used_at'], '203.0.113.7')


def test_key_use_bookkeeping_never_fails_or_stalls_a_request(accounts, monkeypatch):
    service, store = accounts.service, accounts.store
    account = siem(service)
    record, _ = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    stale = '2020-01-01T00:00:00.000000+00:00'
    store.execute('UPDATE service_account_keys SET last_used_at=?', (stale,))
    release = hold_writer(store)
    try:
        started = time.monotonic()
        service.touch(record['id'], stale, '203.0.113.7')
        assert time.monotonic() - started < 5
    finally:
        release()
    assert store.rows('SELECT last_used_at FROM service_account_keys')[0]['last_used_at'] == stale  # Skipped.
    connect = store.connect

    def busy(**kwargs):
        if kwargs.get('write_scope') == 'service-key-use':
            raise DatabaseBusyError('Postgres is busy; the transaction was not acknowledged.')
        return connect(**kwargs)
    monkeypatch.setattr(store, 'connect', busy)
    service.touch(record['id'], stale, '203.0.113.7')
    monkeypatch.setattr(store, 'connect', connect)
    service.touch(record['id'], stale, '203.0.113.7')
    assert store.rows('SELECT last_used_at FROM service_account_keys')[0]['last_used_at'] > stale


def test_service_principals_never_perform_governance_changes(accounts):
    service = accounts.service
    account = siem(service)
    record, _ = service.create_key(account['id'], ServiceKeyCreate(label='Splunk'), OWNER)
    principal = SimpleNamespace(id=f"service:{account['id']}:{record['id']}", kind='service', method='api_key',
                                email='', role='member', permissions=frozenset({'audit.read', 'service_accounts.manage'}))
    actor = GovernanceActor.from_principal(principal)
    assert actor.resolved_kind == 'service' and actor.email == ''
    with accounts.store.connect() as conn:
        with pytest.raises(GovernanceForbidden):
            accounts.roles.enterprise.authority_in(conn, actor)
    for attempt, *arguments in ((service.listing,), (service.revoke_key, account['id'], record['id']),
                                (service.disable, account['id'], 1),
                                (service.create, ServiceAccountCreate(name='Escalation', permissions=['audit.read'])),
                                (service.create_key, account['id'], ServiceKeyCreate(label='Escalation'))):
        with pytest.raises(GovernanceForbidden):
            attempt(*arguments, principal)


def test_listing_states_key_status_routes_and_recent_activity(accounts):
    service, store = accounts.service, accounts.store
    account = siem(service, permissions=['spend.read'])
    active, _ = service.create_key(account['id'], ServiceKeyCreate(label='Active'), OWNER)
    expired, _ = service.create_key(account['id'], ServiceKeyCreate(label='Expired'), OWNER)
    revoked, _ = service.create_key(account['id'], ServiceKeyCreate(label='Revoked'), OWNER)
    service.revoke_key(account['id'], revoked['id'], OWNER)
    store.execute("UPDATE service_account_keys SET expires_at='2020-01-01T00:00:00.000000+00:00' WHERE id=?",
                  (expired['id'],))
    listing = service.listing(OWNER)
    assert listing['permission_ceiling'] == ['audit.read', 'spend.read'] and listing['max_active_keys'] == MAX_ACTIVE_KEYS
    assert listing['key_routes'] == [{'method': 'GET', 'path': path, 'permission': permission}
                                     for (_, path), permission in API_KEY_ROUTES.items()]
    statuses = {key['label']: key['status'] for key in listing['accounts'][0]['keys']}
    assert statuses == {'Active': 'active', 'Expired': 'expired', 'Revoked': 'revoked'}
    assert [entry['action'] for entry in listing['activity']][0] == 'service_account_key.revoked'
    assert {entry['resource_type'] for entry in listing['activity']} == {'service_account', 'service_account_key'}
    feed = GovernanceAudit(store, b'service-account-audit-secret')
    for resource_type, actions in (('service_account', {'service_account.created'}),
                                   ('service_account_key', {'service_account_key.created', 'service_account_key.revoked'})):
        page = feed.listing(parse_filters(resource_type=resource_type))
        assert {entry['action'] for entry in page['entries']} == actions
    assert {'service_account', 'service_account_key'} <= set(feed.listing()['facets']['resource_types'])
    assert active['id'] in json.dumps(listing)


def test_key_routes_are_exact_reads_inside_the_ceiling():
    assert set(API_KEY_ROUTES.values()) == SERVICE_PERMISSIONS and SERVICE_PERMISSIONS <= set(PERMISSIONS)
    assert not SERVICE_PERMISSIONS & MEMBER_PERMISSIONS and 'service_accounts.manage' not in MEMBER_PERMISSIONS
    for (method, path), permission in API_KEY_ROUTES.items():
        assert method == 'GET' and api_key_route(method, path) == permission
        assert route_permission(SimpleNamespace(scope={'path': path}, method=method)) == permission
        for other in ('HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS'):
            assert api_key_route(other, path) is None
        for variant in (path + '/', path + 'x', path.upper(), path + '/../roles'):
            assert api_key_route(method, variant) is None
    assert api_key_route('GET', '/api/admin/spend-limits') is None and api_key_route('GET', '/api/spend') is None
    assert route_permission(SimpleNamespace(scope={'path': '/api/admin/service-accounts/x/keys'}, method='GET')) \
        == 'service_accounts.manage'
