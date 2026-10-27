"""API key authentication boundaries over a local canonical SQLite source; no provider calls."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import test_product_identity as identity_fixtures
from app.db import Store
from app.enterprise_roles import GovernanceActor
from app.security import Throttle
from app.service_accounts import ServiceAccountCreate, ServiceAccounts, ServiceKeyCreate, digest, mint
from app.user_roles import UserRoles
from fastapi import APIRouter, FastAPI, HTTPException, Request
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from test_product_identity import cloudflare_setup, google_cookie, settings_for

from moyai.product_identity import ProductIdentityAdapter
from moyai.product_resources import ProductResources

product = identity_fixtures.product

AUDIT, EXPORT, SPEND = '/api/admin/governance/audit', '/api/admin/governance/audit/export', '/api/admin/spend'
INVALID = 'A valid API key is required.'
ELSEWHERE = 'API keys cannot access this endpoint.'


async def issue(engine, *, table=lambda name: name, permissions=('audit.read',), days=30, active=1, account=None):
    """A key stored exactly as ServiceAccounts.create_key stores it; the token is returned here only."""
    account = account or uuid4().hex
    key_id, token, prefix = mint()
    created = datetime.now(UTC)
    stamp = created.isoformat(timespec='microseconds')
    async with engine.begin() as db:
        await db.execute(text(
            f"INSERT INTO {table('service_accounts')}(id,name,name_key,description,permissions,revision,"
            "access_revision,active,created_by,created_at,updated_by,updated_at) VALUES (:id,:name,:name_key,'',"
            ":permissions,1,1,:active,'owner@example.test',:stamp,'owner@example.test',:stamp) ON CONFLICT(id) DO NOTHING"
        ), {'id': account, 'name': 'SIEM ' + account[:8], 'name_key': 'siem ' + account[:8], 'active': active,
            'permissions': '["' + '","'.join(sorted(permissions)) + '"]', 'stamp': stamp})
        await db.execute(text(
            f"INSERT INTO {table('service_account_keys')}(id,account_id,label,token_hash,prefix,created_by,"
            "created_at,expires_at,last_used_at,last_used_from,revoked_at,revoked_by) VALUES (:id,:account,'Splunk',"
            ":hash,:prefix,'owner@example.test',:created,:expires,'','','','')"
        ), {'id': key_id, 'account': account, 'hash': digest(token), 'prefix': prefix, 'created': stamp,
            'expires': (created + timedelta(days=days)).isoformat(timespec='microseconds')})
    return SimpleNamespace(account=account, key=key_id, token=token, prefix=prefix,
                           header={'authorization': 'Bearer ' + token})


async def change(engine, sql, *, table=lambda name: name, **values):
    async with engine.begin() as db:
        await db.execute(text(sql.format(accounts=table('service_accounts'), keys=table('service_account_keys'))),
                         values)


def key_request(path, token='', *, method='GET', cookie='', headers=None, client='127.0.0.1'):
    values = {'authorization': 'Bearer ' + token} if token else {}
    if cookie:
        values['cookie'] = f'workspace_session={cookie}'
    values.update(headers or {})
    return Request({
        'type': 'http', 'method': method, 'path': path, 'query_string': b'', 'scheme': 'http',
        'server': ('127.0.0.1', 8787), 'client': (client, 1234), 'state': {},
        'headers': [(name.lower().encode(), value.encode()) for name, value in values.items()],
    })


async def refused(adapter, request, **kwargs):
    with pytest.raises(HTTPException) as error:
        await adapter.authenticate(request, **kwargs)
    return error.value


async def test_a_key_reads_only_its_allowlisted_routes_as_a_bounded_service_principal(product):
    adapter = product.adapter
    key = await issue(product.writer, permissions=('audit.read', 'spend.read', 'roles.manage'))
    request = key_request(AUDIT, key.token)
    principal = await adapter.authenticate(request, admin=True)
    assert (principal.id, principal.kind, principal.method, principal.email, principal.role) == (
        f'service:{key.account}:{key.key}', 'service', 'api_key', '', 'member')
    # Stored permissions outside the ceiling grant nothing.
    assert principal.permissions == principal.effective_permissions == frozenset({'audit.read', 'spend.read'})
    assert not principal.individual and principal.csrf_token == '' and principal.name == 'SIEM ' + key.account[:8]
    assert request.state.product_identity_grant == principal.grant
    assert await adapter.require_current(principal.grant) == principal
    for path in (EXPORT, SPEND):
        assert (await adapter.authenticate(key_request(path, key.token), admin=True)).grant == principal.grant
    assert key.token not in repr(principal)
    cookie, csrf = google_cookie(adapter)
    signed_in = {'x-csrf-token': csrf, 'origin': 'http://127.0.0.1:8787'}
    for method, path in (('GET', '/api/me'), ('GET', '/api/permissions'), ('GET', '/api/sessions'),
                         ('GET', '/api/admin/roles'), ('GET', '/api/admin/service-accounts'),
                         ('GET', '/api/settings/billing'), ('GET', '/api/spend'), ('GET', '/api/admin/spend-limits'),
                         ('GET', '/api/product/sessions'), ('GET', '/api/computer/stream'), ('GET', AUDIT + '/'),
                         ('HEAD', AUDIT), ('POST', AUDIT), ('DELETE', '/api/admin/service-accounts/a/keys/b')):
        error = await refused(adapter, key_request(path, key.token, method=method, cookie=cookie, headers=signed_in),
                              mutation=method not in {'GET', 'HEAD'})
        assert (error.status_code, error.detail) == (403, ELSEWHERE), (method, path)
    error = await refused(adapter, key_request(AUDIT, key.token), mutation=True)
    assert (error.status_code, error.detail) == (403, ELSEWHERE)
    # Without the key, the same request is the browser session's own.
    assert (await adapter.authenticate(key_request('/api/me', cookie=cookie))).id == 'google:admin-sub'
    spender = await issue(product.writer, permissions=('spend.read',))
    for path in (AUDIT, EXPORT):
        assert (await refused(adapter, key_request(path, spender.token))).status_code == 403
    assert (await adapter.authenticate(key_request(SPEND, spender.token))).permissions == frozenset({'spend.read'})


async def test_a_key_issued_by_product_resources_authenticates_and_records_its_use_once(tmp_path, monkeypatch):
    """End to end over a canonical store: ServiceAccounts mints the key, the wired adapter accepts it and touches it."""
    settings = settings_for(tmp_path, moyai_database_url='postgresql://unused:unused@127.0.0.1:1/unused')
    native = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'native.db'}")
    resources = ProductResources(settings, native)  # The PostgreSQL engine is never connected here.
    store = Store(tmp_path / 'canonical')
    source = None
    try:
        # Initialize the canonical tables, then serve them through the resources' store proxy.
        ServiceAccounts(store, UserRoles(store, settings))
        resources.store = store
        source = create_async_engine(f'sqlite+aiosqlite:///file:{store.path}?mode=ro&uri=true')
        monkeypatch.setattr(resources.identity, 'source_engine', source)
        monkeypatch.setattr(resources.identity, 'schema', None)
        admin = GovernanceActor(id='google:admin-sub', email='admin@example.test', builtin_role='admin',
                                kind='individual')
        account = resources.service_accounts.create(
            ServiceAccountCreate(name='SIEM collector', permissions=['audit.read']), admin)
        record, token = resources.service_accounts.create_key(account['id'], ServiceKeyCreate(label='Splunk'), admin)

        def used():
            return [(row['last_used_at'], row['last_used_from'])
                    for row in store.rows('SELECT last_used_at,last_used_from FROM service_account_keys')]
        assert used() == [('', '')]
        principal = await resources.identity.authenticate(key_request(AUDIT, token, client='203.0.113.7'))
        assert principal.id == f"service:{account['id']}:{record['id']}"
        assert principal.permissions == frozenset({'audit.read'})
        assert await resources.identity.require_current(principal.grant) == principal
        [(first, network)] = used()
        assert first and network == '203.0.113.7'
        # Within the interval a second request records nothing, even from another network.
        await resources.identity.authenticate(key_request(EXPORT, token, client='198.51.100.1'))
        assert used() == [(first, '203.0.113.7')]
        listed = resources.service_accounts.listing(admin)['accounts'][0]['keys'][0]
        assert (listed['last_used_at'], listed['last_used_from']) == (first, '203.0.113.7')
        resources.service_accounts.revoke_key(account['id'], record['id'], admin)
        error = await refused(resources.identity, key_request(AUDIT, token))
        assert (error.status_code, error.detail) == (401, INVALID)
        with pytest.raises(HTTPException) as ended:
            await resources.identity.require_current(principal.grant)
        assert ended.value.status_code == 401
    finally:
        if source is not None:
            await source.dispose()
        store.close()
        await resources.engine.dispose()
        await native.dispose()


async def test_service_principals_never_gain_member_authority_or_admission(product):
    adapter = product.adapter
    key = await issue(product.writer)
    principal = await adapter.authenticate(key_request(AUDIT, key.token))
    bare = replace(principal, permissions=None)
    assert bare.effective_permissions == frozenset()
    with pytest.raises(HTTPException):
        bare.require('sessions.create')
    async with adapter._reader(product.source) as db:
        # Its email-less branch would grant built-in member permissions.
        assert await adapter.govern_principal(db, bare) is bare
    async with AsyncSession(product.writer) as db:
        for attempt in (adapter.authorize_admission(db, principal.grant), adapter.project_native_user(db, principal),
                        adapter.individual_for_admission(db, principal.grant)):
            with pytest.raises(HTTPException) as denied:
                await attempt
            assert (denied.value.status_code, denied.value.detail) == (403, 'API keys cannot start or continue work.')
    assert GovernanceActor.from_principal(principal).resolved_kind == 'service'


async def test_invalid_keys_get_one_uniform_401_and_never_fall_back_to_the_browser_session(product):
    adapter = product.adapter
    cookie, _ = google_cookie(adapter)
    valid = await issue(product.writer)
    revoked, expired = await issue(product.writer), await issue(product.writer, days=-1)
    disabled = await issue(product.writer, active=0)
    await change(product.writer, "UPDATE {keys} SET revoked_at='2026-10-01T00:00:00.000000+00:00' WHERE id=:id",
                 id=revoked.key)
    unknown = mint()[1]
    wrong = valid.token[:-1] + ('A' if valid.token[-1] != 'A' else 'B')
    for token in (revoked.token, expired.token, disabled.token, unknown, wrong):
        error = await refused(adapter, key_request(AUDIT, token, cookie=cookie))
        assert (error.status_code, error.detail, error.headers) == (401, INVALID, {'WWW-Authenticate': 'Bearer'})
    statements = []
    event.listen(product.source.sync_engine, 'before_cursor_execute',
                 lambda _conn, _cursor, statement, *_args: statements.append(statement))
    for header in ('Bearer moyai_sk_short', 'bearer moyai_sk_' + 'g' * 32 + '.' + 'x' * 43, 'Token ' + valid.token,
                   'Bearer ' + valid.token + '.extra', 'Bearer MOYAI_SK_' + valid.token[9:], 'moyai_sk_' + valid.token):
        error = await refused(adapter, key_request(AUDIT, cookie=cookie, headers={'authorization': header}))
        assert (error.status_code, error.detail) == (401, INVALID), header
    assert statements == [], 'malformed keys are refused before any database read'
    assert (await adapter.authenticate(key_request(AUDIT, valid.token, cookie=cookie))).kind == 'service'
    # Failures are throttled per network, before any database read.
    fresh = ProductIdentityAdapter(product.settings, product.source)
    for _ in range(30):
        assert (await refused(fresh, key_request(AUDIT, wrong))).status_code == 401
    error = await refused(fresh, key_request(AUDIT, valid.token))
    assert error.status_code == 429 and error.headers == {'Retry-After': '60'}


async def test_saved_service_grants_end_with_the_key_the_account_or_a_permission_change(product):
    adapter = product.adapter
    key = await issue(product.writer, permissions=('audit.read', 'spend.read'))
    grant = (await adapter.authenticate(key_request(AUDIT, key.token))).grant

    async def ended(saved):
        with pytest.raises(HTTPException) as error:
            await adapter.require_current(saved)
        assert error.value.status_code == 401
    # Narrowing and widening again advance access_revision, so the earlier grant never revives.
    await change(product.writer, """UPDATE {accounts} SET permissions='["audit.read"]',access_revision=2 WHERE id=:id""",
                 id=key.account)
    await ended(grant)
    await change(product.writer, """UPDATE {accounts} SET permissions='["audit.read","spend.read"]',access_revision=3
        WHERE id=:id""", id=key.account)
    await ended(grant)
    grant = (await adapter.authenticate(key_request(AUDIT, key.token))).grant
    await change(product.writer, "UPDATE {accounts} SET name='Renamed',revision=4 WHERE id=:id", id=key.account)
    assert (await adapter.require_current(grant)).name == 'Renamed'
    await change(product.writer, "UPDATE {keys} SET revoked_at='2026-10-01T00:00:00.000000+00:00' WHERE id=:id",
                 id=key.key)
    await ended(grant)
    second = await issue(product.writer, account=key.account)
    grant = (await adapter.authenticate(key_request(AUDIT, second.token))).grant
    await change(product.writer, "UPDATE {keys} SET expires_at='2020-01-01T00:00:00.000000+00:00' WHERE id=:id",
                 id=second.key)
    await ended(grant)
    third = await issue(product.writer, account=key.account)
    grant = (await adapter.authenticate(key_request(AUDIT, third.token))).grant
    await change(product.writer, 'UPDATE {accounts} SET active=0 WHERE id=:id', id=key.account)
    await ended(grant)
    # A grant naming another account than its key's is refused, as is a malformed id.
    other = await issue(product.writer)
    other_grant = (await adapter.authenticate(key_request(AUDIT, other.token))).grant
    await ended(replace(other_grant, user_id=f'service:{key.account}:{other.key}'))
    await ended(replace(other_grant, user_id='service:' + other.key))


async def test_each_key_is_rate_limited_and_its_use_is_recorded_best_effort(product):
    adapter, calls = product.adapter, []
    key = await issue(product.writer)
    adapter.service_key_touch = lambda key_id, last_used_at, network: calls.append((key_id, last_used_at, network))
    await adapter.authenticate(key_request(AUDIT, key.token))
    assert calls == [(key.key, '', '127.0.0.1')]
    recent = datetime.now(UTC).isoformat(timespec='microseconds')
    await change(product.writer, 'UPDATE {keys} SET last_used_at=:recent WHERE id=:id', recent=recent, id=key.key)
    await adapter.authenticate(key_request(AUDIT, key.token))
    assert len(calls) == 1, 'a recent use is not written again'

    def failing(*_args):
        raise RuntimeError('canonical store unavailable')
    adapter.service_key_touch = failing
    await change(product.writer, "UPDATE {keys} SET last_used_at='' WHERE id=:id", id=key.key)
    assert (await adapter.authenticate(key_request(AUDIT, key.token))).kind == 'service'
    adapter.key_rate = Throttle(2)
    for _ in range(2):
        await adapter.authenticate(key_request(AUDIT, key.token))
    assert (await refused(adapter, key_request(AUDIT, key.token))).status_code == 429


async def test_the_spend_report_accepts_a_key_without_activity_or_personal_paths(product):
    from moyai.product_billing_routes import routes

    key = await issue(product.writer, permissions=('spend.read',))
    reports = []

    class Billing:
        identity = product.adapter

        async def report(self, **values):
            reports.append(values)
            return {'daily': [{'day': '2026-10-01', 'cost_usd': 1.25}]}
    app = FastAPI()
    app.include_router(routes(Billing()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8787',
                                 headers=key.header) as client:
        response = await client.get(SPEND, params={'format': 'csv', 'export': 'daily'})
        assert response.status_code == 200 and response.text.splitlines() == ['day,cost_usd', '2026-10-01,1.25']
        assert response.headers['cache-control'] == 'no-store'
        assert reports[0]['viewer_id'] == f'service:{key.account}:{key.key}' and reports[0]['personal'] is False
        for path, params in ((SPEND, {'include_activity': 'true', 'format': 'csv', 'export': 'turns'}),
                             ('/api/settings/billing', {}), ('/api/spend', {})):
            assert (await client.get(path, params=params)).status_code == 403, path
    assert len(reports) == 1


async def test_access_exempts_only_allowlisted_key_reads_and_keys_are_refused_everywhere_else(
        product, runtime, monkeypatch, caplog):
    from moyai.api import create_app

    adapter, cookie, _, _, assertion = await cloudflare_setup(product)
    key = await issue(product.writer)
    reached = []

    class Audit:
        def listing(self, filters, cursor, limit):
            reached.append('listing')
            return {'entries': [], 'next_cursor': None, 'facets': None}

        def export(self, filters, format):
            reached.append('export')
            return iter(['{"id":"1","source":"governance"}\n'])
    # Restore the runtime's product before the runtime fixture closes it.
    with monkeypatch.context() as patch:
        patch.setattr(runtime, 'product', SimpleNamespace(
            settings=adapter.settings, identity=adapter, scim=SimpleNamespace(router=APIRouter), audit=Audit(),
            google=SimpleNamespace(routes=APIRouter), oidc=SimpleNamespace(routes=APIRouter),
            security=SimpleNamespace(access_session=lambda _request, _identity: None),
        ))
        patch.setattr(runtime, 'product_identity', adapter)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(runtime, run_dispatcher=False)),
                                     base_url=adapter.settings.public_url) as client:
            listed = await client.get(AUDIT, headers=key.header)
            assert listed.status_code == 200, listed.text
            assert listed.json() == {'entries': [], 'next_cursor': None, 'facets': None}
            assert listed.headers['cache-control'] == 'no-store' and 'set-cookie' not in listed.headers
            exported = await client.get(EXPORT, params={'format': 'ndjson'}, headers=key.header)
            assert exported.status_code == 200 and exported.text == '{"id":"1","source":"governance"}\n'
            assert reached == ['listing', 'export']
            # Without a key, the same paths still need Access; a key in the query string is not a key.
            for params in ({}, {'api_key': key.token, 'token': key.token}):
                denied = await client.get(AUDIT, params=params)
                assert denied.status_code == 401 and denied.json() == {'detail': 'A valid organization sign-in is required.'}
            # Anywhere else a key is refused before Access, the browser session and every handler.
            caplog.set_level(logging.INFO, logger='moyai.api_keys')
            signed_in = {**key.header, 'cf-access-jwt-assertion': assertion, 'cookie': f'workspace_session={cookie}'}
            for method, path in (('GET', '/api/me'), ('GET', '/api/admin/roles'), ('GET', '/api/admin/service-accounts'),
                                 ('POST', '/api/admin/service-accounts'), ('POST', AUDIT), ('HEAD', AUDIT),
                                 ('GET', '/api/spend'), ('GET', '/api/settings/billing'), ('GET', '/api/sessions'),
                                 ('PATCH', '/scim/v2/Users/' + '0' * 32), ('GET', '/health')):
                response = await client.request(method, path, headers=signed_in)
                assert response.status_code == 403, (method, path)
                if method != 'HEAD':
                    assert response.json() == {'detail': ELSEWHERE}
            assert reached == ['listing', 'export']
            # Each probe leaves a trace by prefix; a malformed key is logged without any part of it.
            refusals = [record.getMessage() for record in caplog.records
                        if record.name == 'moyai.api_keys' and 'refused: route' in record.getMessage()]
            assert len(refusals) == 11 and all(f'prefix={key.prefix} ' in line for line in refusals)
            caplog.clear()
            assert (await client.get('/api/me', headers={'authorization': key.header['authorization'] + 'x'})).status_code == 403
            [line] = [record.getMessage() for record in caplog.records if record.name == 'moyai.api_keys']
            assert 'prefix=malformed ' in line and "path='/api/me'" in line
            assert key.token.partition('.')[2] not in caplog.text and key.token not in caplog.text
            # Once revoked, the key is refused before any handler runs.
            await change(product.writer, "UPDATE {keys} SET revoked_at='2026-10-01T00:00:00.000000+00:00' WHERE id=:id",
                         id=key.key)
            response = await client.get(AUDIT, headers=key.header)
            assert response.status_code == 401 and response.json() == {'detail': INVALID}
            assert reached == ['listing', 'export']


async def test_keys_are_never_logged_or_echoed(product, caplog):
    adapter = product.adapter
    key = await issue(product.writer)
    secret = key.token.partition('.')[2]
    wrong = key.token[:-1] + ('A' if key.token[-1] != 'A' else 'B')
    caplog.set_level(logging.DEBUG)
    errors = []
    await adapter.authenticate(key_request(AUDIT, key.token))
    for token, path in ((wrong, AUDIT), (key.token, '/api/me'), (key.token + 'x', AUDIT)):
        errors.append(await refused(adapter, key_request(path, token)))
    assert any(record.name == 'moyai.api_keys' for record in caplog.records)
    logged = caplog.text + ''.join(repr(record.args) for record in caplog.records)
    shown = ' '.join(f'{error.detail} {error.headers}' for error in errors)
    for text_ in (logged, shown):
        assert key.token not in text_ and secret not in text_ and wrong.partition('.')[2] not in text_
    assert key.prefix in caplog.text, 'accepted requests are logged by prefix'
