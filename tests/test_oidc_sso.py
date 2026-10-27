"""Organization OpenID Connect sign-in against a fake identity provider, on SQLite or --postgres-backend.

The provider is an httpx.MockTransport: discovery, signing keys and the token
endpoint are synthetic and no request leaves the process. The router runs on a
small FastAPI app with the canonical Store, UserRoles and Security.
"""
import base64
import hashlib
import json
import time
from http.cookies import SimpleCookie
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from app import governance_activity, oidc_sso, sign_in_audit
from app.config import Settings
from app.database import DatabaseError
from app.db import IdentityRefused, Store
from app.enterprise_roles import GovernanceActor, RoleAssignment, RoleCreate
from app.google_sso import GoogleSignIn
from app.oidc_sso import OidcSignIn, state_digest
from app.permissions import BUILTIN_PERMISSIONS
from app.schema_migrations import initialize_components
from app.security import Security, digest
from app.user_roles import UserRoles
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import Response

ORIGIN = 'http://127.0.0.1:8787'
ISSUER = 'https://idp.example.test/oauth2/default'
CLIENT = 'synthetic-okta-client'
SECRET = 'synthetic-okta-secret'
OKTA = {'id': 'okta', 'label': 'Okta', 'issuer': ISSUER, 'client_id': CLIENT, 'domains': ['example.test']}
OWNER = GovernanceActor(id='google:owner', email='admin@example.test', builtin_role='admin', kind='individual')


class FakeProvider:
    """Discovery, keys and a token endpoint for one synthetic issuer."""

    def __init__(self, issuer=ISSUER, client_id=CLIENT, secret=SECRET, algorithm='RS256'):
        self.issuer, self.client_id, self.secret, self.algorithm = issuer, client_id, secret, algorithm
        self.key = (ec.generate_private_key(ec.SECP256R1()) if algorithm == 'ES256'
                    else rsa.generate_private_key(public_exponent=65537, key_size=2048))
        base = issuer.split('/oauth2')[0]
        self.document = {'issuer': issuer, 'authorization_endpoint': base + '/authorize',
                         'token_endpoint': base + '/token', 'jwks_uri': base + '/keys',
                         'response_types_supported': ['code'], 'code_challenge_methods_supported': ['S256']}
        self.keys = [self.jwk(self.key.public_key(), 'key-1')]
        self.requests, self.claims, self.header, self.responses = [], {}, {}, {}
        self.signing_key = self.key
        self.code = 'synthetic-code'
        self.authorization = {}
        self.client_auth = 'client_secret_basic'

    def jwk(self, public, kid, **extra):
        family = jwt.algorithms.ECAlgorithm if self.algorithm == 'ES256' else jwt.algorithms.RSAAlgorithm
        return {**family.to_jwk(public, as_dict=True), 'kid': kid, 'use': 'sig', **extra}

    def token(self, **overrides):
        now = int(time.time())
        claims = {'iss': self.issuer, 'aud': self.client_id, 'sub': 'okta-subject', 'iat': now, 'exp': now + 300,
                  'nonce': self.authorization.get('nonce'), 'email': 'person@example.test',
                  'email_verified': True, 'name': 'Synthetic  Person'}
        claims.update(self.claims, **overrides)
        claims = {key: value for key, value in claims.items() if value is not None}
        header = {'kid': 'key-1', **self.header}
        algorithm = header.pop('alg', self.algorithm)
        return jwt.encode(claims, self.signing_key, algorithm=algorithm, headers=header)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url.copy_with(query=None))
        if url in self.responses:
            response = self.responses[url]
            return response(request) if callable(response) else response
        if url == self.issuer + '/.well-known/openid-configuration':
            return httpx.Response(200, json=self.document)
        if url == self.document['jwks_uri']:
            return httpx.Response(200, json={'keys': self.keys})
        if url == self.document['token_endpoint']:
            form = parse_qs(request.content.decode())
            if self.client_auth == 'client_secret_basic':
                expected = 'Basic ' + base64.b64encode(f'{self.client_id}:{self.secret}'.encode()).decode()
                assert request.headers['authorization'] == expected and 'client_secret' not in form
            else:
                assert 'authorization' not in request.headers
                assert form['client_id'] == [self.client_id] and form['client_secret'] == [self.secret]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form['code_verifier'][0].encode()).digest())
            assert challenge.rstrip(b'=').decode() == self.authorization['code_challenge']
            assert form['grant_type'] == ['authorization_code'] and form['code'] == [self.code]
            assert form['redirect_uri'] == [self.authorization['redirect_uri']]
            return httpx.Response(200, json={'id_token': self.token(), 'token_type': 'Bearer', 'access_token': 'unused'})
        return httpx.Response(404)

    def serves(self, url):
        return url.startswith(self.issuer) or url in self.responses or url in {
            self.document['authorization_endpoint'], self.document['token_endpoint'], self.document['jwks_uri']}

    def fetched(self, suffix):
        return sum(1 for request in self.requests if str(request.url).endswith(suffix))


def settings_for(tmp_path, providers=(OKTA,), secrets=None, **overrides):
    values = {'_env_file': None, 'data_dir': tmp_path, 'public_url': ORIGIN,
              'session_secret': 'synthetic-oidc-session-secret', 'encryption_key': Fernet.generate_key().decode(),
              'google_allowed_domains': 'example.test,other.test,partner.test',
              'google_admin_emails': 'admin@example.test',
              'oidc_providers': list(providers),
              'oidc_client_secrets': secrets if secrets is not None else {
                  item['id']: SECRET for item in providers}}
    values.update(overrides)
    return Settings(**values)


def service(store, settings, idp, extra=()):
    roles = UserRoles(store, settings)
    security = Security(settings, roles)

    def route(request):
        url = str(request.url.copy_with(query=None))
        owner = next((provider for provider in (idp, *extra) if provider.serves(url)), None)
        return owner.handle(request) if owner else httpx.Response(404)

    oidc = OidcSignIn(settings, security, store, transport=httpx.MockTransport(route))
    app = FastAPI()
    app.include_router(oidc.routes())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN)
    return SimpleNamespace(store=store, settings=settings, roles=roles, security=security,
                           oidc=oidc, client=client, idp=idp)


@pytest.fixture
async def product(tmp_path):
    store = Store(tmp_path)
    initialize_components(store)
    clients = []

    def serve(settings=None, idp=None, extra=()):
        """Another router on the same store; its client closes with the fixture."""
        current = service(store, settings or settings_for(tmp_path), idp or FakeProvider(), extra)
        clients.append(current.client)
        return current

    current = serve()
    current.serve = serve
    try:
        yield current
    finally:
        for client in clients:
            await client.aclose()
        store.close()


async def start(product, provider='okta', return_to='/#connections'):
    response = await product.client.post(f'/api/auth/oidc/{provider}/start', json={'return_to': return_to},
                                         headers={'origin': ORIGIN})
    assert response.status_code == 200, response.text
    url = urlsplit(response.json()['url'])
    params = {key: values[0] for key, values in parse_qs(url.query).items()}
    return url, params, response


async def sign_in(product, provider='okta', *, code=None, **query):
    idp = product.idp
    _, params, _ = await start(product, provider)
    idp.authorization = params
    query = {'state': params['state'], 'code': idp.code if code is None else code, **query}
    return await product.client.get(f'/auth/oidc/{provider}/callback',
                                    params={key: value for key, value in query.items() if value is not None})


def session(product, response=None):
    cookie = (response.cookies if response is not None else product.client.cookies).get('workspace_session')
    return product.security.signer.loads(cookie) if cookie else None


def issued(security, identity):
    """A signed Google session cookie value, as the Google callback issues it."""
    response = Response()
    security.new_session(response, 'member', identity=identity)
    cookie = SimpleCookie()
    cookie.load(response.headers['set-cookie'])
    return cookie['workspace_session'].value


def request_with(cookie=None):
    headers = [(b'cookie', f'workspace_session={cookie}'.encode())] if cookie else []
    return Request({'type': 'http', 'method': 'GET', 'path': '/api/me', 'query_string': b'', 'state': {},
                    'headers': headers})


def events(product, action=None):
    rows = product.store.rows('SELECT action,actor,resource_type,resource_id,details FROM governance_audit_events '
                              'ORDER BY created_at,id')
    return [{**row, 'details': json.loads(row['details'])} for row in rows if action in {None, row['action']}]


def refused(product):
    return [event['details']['reason'] for event in events(product, 'sign_in.refused')]


def assert_failed(product, response, reason=None):
    assert response.status_code == 303
    assert response.headers['location'].startswith('/?signin=failed')
    assert 'workspace_session' not in response.cookies
    if reason:
        assert refused(product)[-1] == reason


def raising(error):
    def fail(*args, **kwargs):
        raise error
    return fail


async def test_code_flow_with_pkce_pins_a_new_account_and_audits_it(product):
    url, params, started = await start(product)
    assert (url.scheme, url.netloc, url.path) == ('https', 'idp.example.test', '/authorize')
    assert params['client_id'] == CLIENT and params['response_type'] == 'code'
    assert params['redirect_uri'] == ORIGIN + '/auth/oidc/okta/callback'
    assert params['scope'] == 'openid email profile' and params['code_challenge_method'] == 'S256'
    assert len(params['state']) >= 43 and len(params['nonce']) >= 43 and 'prompt' not in params
    cookie = started.headers['set-cookie'].lower()
    assert cookie.startswith('oidc_login=') and 'path=/auth/oidc/okta' in cookie and 'httponly' in cookie
    stored = product.store.rows('SELECT state_hash,nonce FROM login_states')
    assert stored == [{'state_hash': state_digest('okta', params['state']), 'nonce': params['nonce']}]

    product.idp.authorization = params
    response = await product.client.get('/auth/oidc/okta/callback', params={'state': params['state'], 'code': 'synthetic-code'})
    assert response.status_code == 303 and response.headers['location'] == '/#connections'
    info = session(product, response)
    user_id = 'oidc:' + hashlib.sha256(f'{ISSUER}\0okta-subject'.encode()).hexdigest()
    assert info['method'] == 'oidc' and info['client_id'] == CLIENT and info['role'] == 'member'
    assert info['identity'] == {'provider': 'okta', 'issuer': ISSUER, 'sub': 'okta-subject',
                                'email': 'person@example.test', 'domain': 'example.test', 'name': 'Synthetic Person'}
    assert product.store.rows('SELECT id,kind,email,name FROM users') == [
        {'id': user_id, 'kind': 'oidc', 'email': 'person@example.test', 'name': 'Synthetic Person'}]
    assert product.store.rows('SELECT issuer,subject,email,user_id FROM access_identities') == [
        {'issuer': ISSUER, 'subject': 'okta-subject', 'email': 'person@example.test', 'user_id': user_id}]
    assert not product.store.rows('SELECT 1 FROM login_states')
    assert [(event['action'], event['actor'], event['resource_type'], event['resource_id'], event['details'])
            for event in events(product)] == [
        ('identity_binding.created', 'person@example.test', 'identity_binding', user_id,
         {'provider': 'okta', 'linked_existing': False}),
        ('sign_in.succeeded', 'person@example.test', 'sign_in', 'okta', {'method': 'oidc', 'enrolled': True})]
    # Store.identity resolves the pinned account; it never enrolls from a cookie.
    assert product.store.identity(info) == user_id

    again = await sign_in(product)
    assert again.status_code == 303 and session(product, again)['identity']['sub'] == 'okta-subject'
    assert [event['details'] for event in events(product, 'sign_in.succeeded')][-1] == {'method': 'oidc', 'enrolled': False}
    assert len(events(product, 'identity_binding.created')) == 1


def access_service(product, tmp_path):
    settings = settings_for(tmp_path, cloudflare_access_login=True, public_url='https://workspace.example.test',
                            cloudflare_access_team_domain='synthetic.cloudflareaccess.com',
                            cloudflare_access_audience='employee', cloudflare_access_broker_audience='broker')
    return Security(settings, UserRoles(product.store, settings))


async def test_session_follows_live_provider_configuration_and_custom_roles(product, tmp_path):
    response = await sign_in(product)
    cookie = response.cookies['workspace_session']
    info = product.security.session_info(request_with(cookie))
    assert info['method'] == 'oidc' and info['_permissions'] == BUILTIN_PERMISSIONS['member']
    # Custom roles narrow OIDC sessions exactly as Google sessions.
    product.roles.enterprise.create(RoleCreate(id='reader', name='Reader', permissions=['sessions.read']), OWNER)
    product.roles.enterprise.assign(RoleAssignment(email='person@example.test', role_id='reader'), OWNER)
    info = product.security.session_info(request_with(cookie))
    assert product.security.permissions_for_info(info) == frozenset({'sessions.read'})

    other = {**OKTA, 'id': 'entra', 'issuer': 'https://login.microsoftonline.com/tenant/v2.0'}
    for changed in (settings_for(tmp_path, providers=()),
                    settings_for(tmp_path, providers=({**OKTA, 'client_id': 'rotated'},)),
                    settings_for(tmp_path, providers=({**OKTA, 'issuer': ISSUER + '2'},)),
                    settings_for(tmp_path, providers=({**OKTA, 'domains': ['partner.test']},
                                                      {**other, 'domains': ['example.test']})),
                    access_service(product, tmp_path).settings):
        assert Security(changed, UserRoles(product.store, changed)).session_info(request_with(cookie)) is None
    assert Security(product.settings, product.roles).session_info(request_with(cookie))['method'] == 'oidc'


def google_service(product, tmp_path, domain='other.test', **overrides):
    """Google sign-in whose token exchange is a correctly signed synthetic ID token."""
    settings = settings_for(tmp_path, google_client_id='google-client', google_client_secret='google-secret',
                            **overrides)
    google = GoogleSignIn(settings, Security(settings, UserRoles(product.store, settings)), product.store)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    async def signing_key(kid):
        return key.public_key()

    async def exchange(code, verifier, nonce):
        now = int(time.time())
        token = jwt.encode({'iss': 'https://accounts.google.com', 'aud': 'google-client', 'sub': 'google-subject',
                            'iat': now, 'exp': now + 300, 'nonce': nonce, 'email': 'person@' + domain,
                            'email_verified': True, 'hd': domain}, key, algorithm='RS256', headers={'kid': 'k'})
        return await google.verify(token, nonce)

    google.signing_key, google.exchange = signing_key, exchange
    app = FastAPI()
    app.include_router(google.routes())
    return google, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN)


async def google_callback(client, **query):
    started = await client.post('/api/auth/google/start', json={}, headers={'origin': ORIGIN})
    state = parse_qs(urlsplit(started.json()['url']).query)['state'][0]
    return await client.get('/auth/google/callback', params={'state': state, 'code': 'synthetic-code', **query})


async def test_google_does_not_sign_in_or_keep_sessions_for_claimed_domains(product, tmp_path):
    settings = settings_for(tmp_path, google_client_id='google-client', google_client_secret='google-secret')
    security = Security(settings, UserRoles(product.store, settings))
    claimed = issued(security, {'sub': 'g', 'email': 'person@example.test', 'domain': 'example.test', 'name': 'P'})
    unclaimed = issued(security, {'sub': 'g', 'email': 'person@other.test', 'domain': 'other.test', 'name': 'P'})
    assert security.session_info(request_with(claimed)) is None
    assert security.session_info(request_with(unclaimed))['method'] == 'google'
    assert settings.google_signin_domains() == {'other.test', 'partner.test'}

    _, client = google_service(product, tmp_path, google_allowed_domains='example.test')
    async with client:
        blocked = await client.post('/api/auth/google/start', json={}, headers={'origin': ORIGIN})
    assert blocked.status_code == 409


async def test_google_callback_refuses_a_verified_identity_in_a_claimed_domain(product, tmp_path):
    _, client = google_service(product, tmp_path, domain='example.test')
    async with client:
        response = await google_callback(client)
    assert_failed(product, response)
    assert response.headers['location'] == '/?signin=failed#tasks' and not product.store.rows('SELECT 1 FROM users')


@pytest.mark.parametrize('claims, header, reason', [
    ({'iss': 'https://evil.example.test'}, {}, 'token'),
    ({'aud': 'another-client'}, {}, 'token'),
    ({'aud': [CLIENT, 'another-client']}, {}, 'token'),
    ({'azp': 'another-client'}, {}, 'token'),
    ({'exp': int(time.time()) - 120}, {}, 'token'),
    ({'iat': int(time.time()) + 600}, {}, 'token'),
    ({'nonce': 'replayed-nonce'}, {}, 'token'),
    ({'nonce': None}, {}, 'token'),
    ({}, {'kid': 'unknown-key'}, 'token'),
    ({'sub': ''}, {}, 'claims'),
    ({'sub': 's' * 256}, {}, 'claims'),
    ({'email': 'a' * 250 + '@example.test'}, {}, 'claims'),
    ({'email': None}, {}, 'claims'),
    ({'email_verified': False}, {}, 'email_unverified'),
    ({'email_verified': None}, {}, 'email_unverified'),
    ({'email_verified': 'true'}, {}, 'email_unverified'),
    ({'email': 'person@partner.test'}, {}, 'domain'),
    ({'email': 'person@unlisted.test'}, {}, 'domain'),
])
async def test_token_and_claim_failures_redirect_without_a_session(product, claims, header, reason):
    product.idp.claims, product.idp.header = claims, header
    response = await sign_in(product)
    assert_failed(product, response, reason)
    refusal = events(product, 'sign_in.refused')[-1]
    assert refusal['actor'] == 'anonymous' and refusal['details'] == {'method': 'oidc', 'reason': reason}
    assert 'synthetic-code' not in response.headers['location']


def freeze_minute(monkeypatch, minute='2026-10-26T09:30'):
    monkeypatch.setattr(governance_activity, 'minute_bucket', lambda: minute)


async def test_unsigned_confused_or_foreign_signatures_are_refused(product, monkeypatch):
    freeze_minute(monkeypatch)
    idp = product.idp
    for header, key in (({'alg': 'none'}, None), ({'alg': 'HS256'}, idp.jwk(idp.key.public_key(), 'x')['n']),
                        ({'alg': 'PS256'}, idp.key), ({}, rsa.generate_private_key(public_exponent=65537, key_size=2048))):
        idp.header, idp.signing_key = header, key
        assert_failed(product, await sign_in(product), 'token')
    # An anonymous refusal is kept once per client network, reason and minute.
    assert len(refused(product)) == 1
    freeze_minute(monkeypatch, '2026-10-26T09:31')
    assert_failed(product, await sign_in(product), 'token')
    assert len(refused(product)) == 2
    assert not product.store.rows('SELECT 1 FROM access_identities')


async def test_signing_keys_are_rate_limited_and_never_symmetric_or_ambiguous(product):
    idp = product.idp
    idp.header = {'kid': 'rotated'}
    assert_failed(product, await sign_in(product), 'token')
    assert_failed(product, await sign_in(product), 'token')
    assert idp.fetched('/keys') == 1  # An unknown key ID refetches at most every 10 seconds.

    for keys in ([{**idp.keys[0]}, {**idp.keys[0]}],
                 [{**idp.keys[0], 'use': 'enc'}],
                 [{'kty': 'oct', 'kid': 'key-1', 'k': base64.urlsafe_b64encode(b'x' * 32).decode()}],
                 [{**idp.keys[0], 'alg': 'PS256'}]):
        fresh = FakeProvider()
        fresh.keys = keys
        fresh.key = fresh.signing_key = idp.key
        current = product.serve(product.settings, fresh)
        assert_failed(current, await sign_in(current), 'unavailable')


async def test_a_verified_document_survives_a_discovery_outage_for_a_day(product, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(oidc_sso, 'time', SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    client, idp = product.oidc.clients['okta'], product.idp
    document = await client.metadata()
    idp.responses[ISSUER + '/.well-known/openid-configuration'] = httpx.Response(500)
    clock[0] += 3601
    assert await client.metadata() is document
    assert idp.fetched('/openid-configuration') == 2
    clock[0] += 30
    assert await client.metadata() is document
    assert idp.fetched('/openid-configuration') == 2  # Retried about once a minute, not per sign-in.
    clock[0] += 31
    assert await client.metadata() is document
    assert idp.fetched('/openid-configuration') == 3
    clock[0] = 1000.0 + 86401
    response = await product.client.post('/api/auth/oidc/okta/start', json={}, headers={'origin': ORIGIN})
    assert response.status_code == 503


async def test_configured_prompt_reaches_the_authorization_request(product, tmp_path):
    current = product.serve(settings_for(tmp_path, providers=({**OKTA, 'prompt': 'login'},)), product.idp)
    _, params, _ = await start(current)
    assert params['prompt'] == 'login'


@pytest.mark.parametrize('change', ['issuer', 'http', 'redirect', 'large', 'unsupported'])
async def test_discovery_must_name_the_exact_issuer_over_https(product, change):
    idp = product.idp
    discovery = ISSUER + '/.well-known/openid-configuration'
    if change == 'issuer':
        idp.document['issuer'] = ISSUER + '/'
    elif change == 'http':
        idp.document['token_endpoint'] = 'http://idp.example.test/token'
    elif change == 'redirect':
        idp.responses[discovery] = httpx.Response(302, headers={'location': 'https://idp.example.test/elsewhere'})
    elif change == 'large':
        idp.responses[discovery] = httpx.Response(200, json={**idp.document, 'padding': 'x' * 70000})
    else:
        idp.document['code_challenge_methods_supported'] = ['plain']
    response = await product.client.post('/api/auth/oidc/okta/start', json={}, headers={'origin': ORIGIN})
    assert response.status_code == 503
    assert not product.store.rows('SELECT 1 FROM login_states')


def token_timeout(request):
    raise httpx.ReadTimeout('synthetic timeout', request=request)


@pytest.mark.parametrize('reply', [
    httpx.Response(400, json={'error': 'invalid_grant'}), httpx.Response(500),
    httpx.Response(200, text='not json'), httpx.Response(200, json={'access_token': 'only'}),
    httpx.Response(200, json={'id_token': 'x' * 40000}), token_timeout,
])
async def test_token_endpoint_failures_echo_nothing(product, reply):
    product.idp.responses['https://idp.example.test/token'] = reply
    response = await sign_in(product)
    assert_failed(product, response, 'token')
    assert response.headers['location'] == '/?signin=failed#connections'


async def test_state_is_bound_to_this_browser_this_provider_and_one_use(product):
    _, params, _ = await start(product)
    product.idp.authorization = params
    query = {'state': params['state'], 'code': 'synthetic-code'}
    product.client.cookies.delete('oidc_login', domain='127.0.0.1', path='/auth/oidc/okta')
    assert_failed(product, await product.client.get('/auth/oidc/okta/callback', params=query))
    product.client.cookies.set('oidc_login', 'other-browser', domain='127.0.0.1', path='/auth/oidc/okta')
    assert_failed(product, await product.client.get('/auth/oidc/okta/callback', params=query))
    assert refused(product) == []  # Nothing was consumed, so nothing is audited.

    response = await sign_in(product)
    assert response.status_code == 303 and response.headers['location'] == '/#connections'
    replay = await product.client.get('/auth/oidc/okta/callback', params={
        'state': product.idp.authorization['state'], 'code': 'synthetic-code'})
    assert replay.headers['location'] == '/?signin=failed#tasks'

    # A Google state, or another provider's state, never redeems here.
    browser = 'shared-browser'
    product.client.cookies.set('oidc_login', browser, domain='127.0.0.1', path='/auth/oidc/okta')
    for state_hash in (digest('google-state'), state_digest('entra', 'google-state')):
        product.store.execute('INSERT INTO login_states(state_hash,browser_hash,nonce,verifier,return_path,expires,client) '
                              'VALUES(?,?,?,?,?,?,?)', (state_hash, digest(browser), 'n', 'v', '/#tasks', time.time() + 600, 'c'))
    failed = await product.client.get('/auth/oidc/okta/callback', params={'state': 'google-state', 'code': 'c'})
    assert failed.headers['location'] == '/?signin=failed#tasks'
    assert len(product.store.rows('SELECT 1 FROM login_states')) == 3  # Including the abandoned first state.
    product.store.execute('UPDATE login_states SET expires=?, state_hash=? WHERE state_hash=?',
                          (time.time() - 1, state_digest('okta', 'expired'), digest('google-state')))
    expired = await product.client.get('/auth/oidc/okta/callback', params={'state': 'expired', 'code': 'c'})
    assert expired.headers['location'] == '/?signin=failed#tasks'


async def test_issuer_parameter_and_cancellation(product, monkeypatch):
    freeze_minute(monkeypatch)
    assert_failed(product, await sign_in(product, iss='https://other.example.test'), 'issuer')
    cancelled = await sign_in(product, code='', error='access_denied')
    assert cancelled.headers['location'] == '/?signin=cancelled#connections'
    assert refused(product)[-1] == 'cancelled'
    assert product.idp.fetched('/token') == 0  # Neither response reached the token endpoint.

    # A provider that promises RFC 9207 responses must send the parameter.
    idp = FakeProvider()
    idp.document['authorization_response_iss_parameter_supported'] = True
    current = product.serve(product.settings, idp)
    assert_failed(current, await sign_in(current))
    # The repeated anonymous refusal in this minute is kept once.
    assert refused(current) == ['issuer', 'cancelled']
    response = await sign_in(current, iss=ISSUER)
    assert response.status_code == 303 and response.headers['location'] == '/#connections'


async def test_start_is_throttled_and_keeps_few_pending_states(product):
    for _ in range(6):
        await start(product)
    assert len(product.store.rows('SELECT 1 FROM login_states')) == 5  # Four kept, plus the newest.
    for _ in range(24):
        await product.client.post('/api/auth/oidc/okta/start', json={}, headers={'origin': ORIGIN})
    blocked = await product.client.post('/api/auth/oidc/okta/start', json={}, headers={'origin': ORIGIN})
    assert blocked.status_code == 429
    assert (await product.client.post('/api/auth/oidc/okta/start', json={})).status_code == 403
    assert (await product.client.post('/api/auth/oidc/unknown/start', json={}, headers={'origin': ORIGIN})).status_code == 404
    assert (await product.client.post('/api/auth/oidc/Bad_Id/start', json={}, headers={'origin': ORIGIN})).status_code == 422


def existing(product, user_id, kind, email='person@example.test'):
    stamp = '2026-10-16T00:00:00+00:00'
    product.store.execute('INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                          (user_id, kind, email, 'Existing', stamp, stamp))


@pytest.mark.parametrize('user_id, kind', [('google:google-subject', 'google'), ('cloudflare:' + 'a' * 64, 'cloudflare')])
async def test_first_sign_in_links_the_one_existing_account(product, user_id, kind):
    existing(product, user_id, kind)
    response = await sign_in(product)
    assert response.status_code == 303 and response.headers['location'] == '/#connections'
    assert product.store.rows('SELECT user_id FROM access_identities') == [{'user_id': user_id}]
    assert product.store.rows('SELECT id FROM users') == [{'id': user_id}]
    assert events(product, 'identity_binding.created')[0]['details'] == {'provider': 'okta', 'linked_existing': True}
    assert product.store.identity(session(product, response)) == user_id


async def test_ambiguous_or_changed_accounts_need_administrator_review(product):
    existing(product, 'google:one', 'google')
    existing(product, 'cloudflare:' + 'b' * 64, 'cloudflare')
    assert_failed(product, await sign_in(product), 'mapping_review')
    assert events(product, 'sign_in.refused')[-1]['actor'] == 'person@example.test'
    product.store.execute("DELETE FROM users WHERE id LIKE 'cloudflare:%'")

    assert (await sign_in(product)).status_code == 303
    product.idp.claims = {'sub': 'second-subject'}  # Same email, another subject at the same issuer.
    assert (await sign_in(product)).headers['location'].startswith('/?signin=failed')
    product.idp.claims = {'email': 'renamed@example.test'}  # The pinned subject's email changed.
    assert (await sign_in(product)).headers['location'].startswith('/?signin=failed')
    assert refused(product)[-2:] == ['mapping_review', 'mapping_review']

    # Removing a binding is never undone from an existing cookie.
    info = session(product)
    product.store.execute('DELETE FROM access_identities')
    with pytest.raises(IdentityRefused):
        product.store.identity(info)
    assert not product.store.rows('SELECT 1 FROM access_identities')


async def test_a_changed_email_is_reviewed_and_recovered_without_a_second_account(product):
    assert (await sign_in(product)).status_code == 303
    user_id = product.store.rows('SELECT user_id FROM access_identities')[0]['user_id']
    product.idp.claims = {'email': 'renamed@example.test'}
    assert_failed(product, await sign_in(product), 'mapping_review')

    # The documented recovery moves the account and its binding together.
    product.store.execute('UPDATE users SET email=? WHERE id=?', ('renamed@example.test', user_id))
    product.store.execute('UPDATE access_identities SET email=? WHERE issuer=? AND subject=?',
                          ('renamed@example.test', ISSUER, 'okta-subject'))
    response = await sign_in(product)
    assert response.status_code == 303 and product.store.identity(session(product, response)) == user_id

    # A recreated provider account for the same person: remove the old subject's binding.
    product.idp.claims = {'sub': 'recreated-subject', 'email': 'renamed@example.test'}
    assert_failed(product, await sign_in(product), 'mapping_review')
    product.store.execute('DELETE FROM access_identities WHERE subject=?', ('okta-subject',))
    assert (await sign_in(product)).status_code == 303
    assert product.store.rows('SELECT subject,user_id FROM access_identities') == [
        {'subject': 'recreated-subject', 'user_id': user_id}]

    # Deleting the binding of a changed email instead fails closed and audited:
    # never a 500, nor a second account for the subject that created this one.
    product.store.execute('DELETE FROM access_identities')
    product.idp.claims = {'sub': 'okta-subject', 'email': 'third@example.test'}
    assert_failed(product, await sign_in(product), 'mapping_review')
    assert product.store.rows('SELECT id FROM users') == [{'id': user_id}]
    with pytest.raises(IdentityRefused):
        product.store.external_identity({'issuer': ISSUER, 'sub': 'okta-subject', 'email': 'third@example.test'},
                                        kind='oidc', provider='okta')


async def test_ascii_emails_only(product, tmp_path):
    # str.lower() turns KELVIN SIGN into 'k': these would otherwise name kate@ and work.test.
    existing(product, 'google:kate', 'google', 'kate@example.test')
    settings = settings_for(tmp_path, providers=({**OKTA, 'domains': ['example.test', 'work.test']},),
                            google_allowed_domains='example.test,work.test')
    current = product.serve(settings, product.idp)
    for email in ('\u212aate@example.test', 'person@wor\u212a.test'):
        current.idp.claims = {'email': email}
        assert_failed(current, await sign_in(current), 'claims')
    assert not product.store.rows('SELECT 1 FROM access_identities')


async def test_display_names_keep_printable_text_only(product):
    product.idp.claims = {'name': ' Synthetic\x00\x1b Person\u2028\t'}
    response = await sign_in(product)
    assert session(product, response)['identity']['name'] == 'Synthetic Person'
    assert product.store.rows('SELECT name FROM users') == [{'name': 'Synthetic Person'}]


async def test_unexpected_failures_redirect_and_log_only_their_type(product, monkeypatch, caplog):
    failing = raising(RuntimeError('synthetic failure for person@example.test'))
    with caplog.at_level('WARNING', logger='app.oidc_sso'):
        # An account failure after verification is unavailable, never a token
        # error, and names the verified person.
        monkeypatch.setattr(product.store, 'external_identity_in',
                            raising(ValueError('synthetic account failure for person@example.test')))
        assert_failed(product, await sign_in(product), 'unavailable')
        monkeypatch.setattr(product.store, 'external_identity_in', failing)
        assert_failed(product, await sign_in(product), 'unavailable')
        monkeypatch.setattr(product.oidc, 'refuse', failing)
        response = await sign_in(product)
    assert response.status_code == 303 and response.headers['location'] == '/?signin=failed#connections'
    assert 'RuntimeError' in caplog.text and 'ValueError' in caplog.text and 'person@example.test' not in caplog.text
    assert [event['actor'] for event in events(product, 'sign_in.refused')] == ['person@example.test'] * 2


async def test_an_inactive_person_rolls_back_the_recorded_sign_in(product, monkeypatch):
    monkeypatch.setattr(product.security, 'person', lambda *args, **kwargs: None)
    assert_failed(product, await sign_in(product), 'deactivated')
    assert [event['action'] for event in events(product)] == ['sign_in.refused']
    assert not product.store.rows('SELECT 1 FROM access_identities')


def scim_user(product, email, active):
    stamp = '2026-10-16T00:00:00+00:00'
    product.store.execute('INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision) '
                          "VALUES(?,'',?,'{}',?,'',?,?,1)", ('a' * 32, email, int(active), stamp, stamp))


async def test_scim_deactivation_and_required_provisioning(product, tmp_path):
    scim_user(product, 'person@example.test', False)
    assert_failed(product, await sign_in(product), 'deactivated')
    product.store.execute('DELETE FROM scim_users')
    earlier = (await sign_in(product)).cookies['workspace_session']

    required = settings_for(tmp_path, providers=({**OKTA, 'require_scim_user': True},))
    current = product.serve(required, product.idp)
    # Requiring provisioning also ends sessions that began without it.
    assert current.security.session_info(request_with(earlier)) is None
    assert_failed(current, await sign_in(current), 'not_provisioned')
    scim_user(current, 'person@example.test', True)
    assert (await sign_in(current)).headers['location'] == '/#connections'
    assert current.security.session_info(request_with(earlier))['method'] == 'oidc'


async def test_entra_style_claims_keys_and_client_secret_post(product, tmp_path):
    tenant = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0'
    idp = FakeProvider(issuer=tenant, client_id='entra-client')
    idp.document.update(authorization_endpoint=tenant.replace('/v2.0', '/oauth2/v2.0/authorize'),
                        token_endpoint=tenant.replace('/v2.0', '/oauth2/v2.0/token'),
                        jwks_uri=tenant.replace('/v2.0', '/discovery/v2.0/keys'))
    idp.keys = [{key: value for key, value in idp.keys[0].items() if key != 'use'}]  # And no 'alg'.
    idp.client_auth = 'client_secret_post'
    idp.claims = {'email_verified': None, 'xms_edov': True, 'email': 'Person@Other.test'}
    entra = {'id': 'entra', 'label': 'Microsoft', 'issuer': tenant, 'client_id': 'entra-client',
             'domains': ['other.test'], 'email_verified_claim': 'xms_edov', 'token_auth': 'client_secret_post'}
    settings = settings_for(tmp_path, providers=(OKTA, entra))
    current = product.serve(settings, product.idp, extra=(idp,))
    current.idp = idp
    response = await sign_in(current, 'entra')
    assert response.status_code == 303, refused(current)
    assert session(current, response)['identity']['email'] == 'person@other.test'
    idp.claims = {'email_verified': True, 'email': 'person@other.test'}  # Only the configured claim counts.
    assert_failed(current, await sign_in(current, 'entra'), 'email_unverified')


async def test_es256_provider(product, tmp_path):
    idp = FakeProvider(algorithm='ES256')
    current = product.serve(settings_for(tmp_path, providers=({**OKTA, 'algorithms': ['ES256']},)), idp)
    assert (await sign_in(current)).headers['location'] == '/#connections'
    idp.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.header = {'alg': 'RS256'}  # Not an allowed algorithm for this provider.
    assert_failed(current, await sign_in(current), 'token')


def sign_ins(product):
    return [(event['action'], event['actor'], event['resource_id'], event['details'])
            for event in events(product) if event['resource_type'] == 'sign_in']


async def test_google_sign_in_success_and_refusals_are_audited_like_oidc(product, tmp_path, monkeypatch):
    freeze_minute(monkeypatch)
    google, client = google_service(product, tmp_path)
    async with client:
        assert (await google_callback(client)).headers['location'] == '/#tasks'
        assert product.store.rows('SELECT id,email FROM users') == [
            {'id': 'google:google-subject', 'email': 'person@other.test'}]
        assert (await google_callback(client)).cookies.get('workspace_session')
        succeeded = [
            ('sign_in.succeeded', 'person@other.test', 'google', {'method': 'google', 'enrolled': True}),
            ('sign_in.succeeded', 'person@other.test', 'google', {'method': 'google', 'enrolled': False})]
        assert sign_ins(product) == succeeded
        # A consumed state that fails records a fixed reason and issues no session.
        cancelled = await google_callback(client, error='access_denied', code='')
        assert cancelled.headers['location'] == '/?signin=cancelled#tasks'
        assert_failed(product, await google_callback(client, code=''), 'token')

        async def failing(code, verifier, nonce):
            raise httpx.ConnectError('synthetic provider failure with sk-live-TOPSECRET')
        with monkeypatch.context() as patch:
            patch.setattr(google, 'exchange', failing)
            # Kept once per client network, reason and minute.
            assert_failed(product, await google_callback(client), 'token')
            freeze_minute(patch, '2026-10-26T09:31')
            assert_failed(product, await google_callback(client), 'token')
        # Unknown or expired states are not recorded.
        assert (await client.get('/auth/google/callback', params={'state': 'forged', 'code': 'x'})).status_code == 303
        assert sign_ins(product)[2:] == [
            ('sign_in.refused', 'anonymous', 'google', {'method': 'google', 'reason': reason})
            for reason in ('cancelled', 'token', 'token')]
        assert 'TOPSECRET' not in json.dumps(events(product))

        # Any refusal after the provider verified the person names them, and an
        # account failure after the exchange is unavailable, not a token error.
        for patched, target, replacement, reason in (
                (google.security, 'person', lambda *args, **kwargs: None, 'deactivated'),
                (product.store, 'identity', raising(IdentityRefused('mapping_review')), 'mapping_review'),
                (product.store, 'identity', raising(ValueError('synthetic account failure for person@other.test')),
                 'unavailable')):
            with monkeypatch.context() as patch:
                patch.setattr(patched, target, replacement)
                assert_failed(product, await google_callback(client), reason)
            assert sign_ins(product)[-1][1:] == ('person@other.test', 'google', {'method': 'google', 'reason': reason})


async def test_google_sign_in_fails_closed_when_its_audit_event_cannot_be_written(product, tmp_path, monkeypatch, caplog):
    _, client = google_service(product, tmp_path)
    monkeypatch.setattr(sign_in_audit, 'succeeded_in',
                        raising(RuntimeError('synthetic audit failure for person@other.test')))
    async with client:
        with caplog.at_level('WARNING', logger='app.google_sso'):
            assert_failed(product, await google_callback(client), 'unavailable')
    assert 'RuntimeError' in caplog.text and 'person@other.test' not in caplog.text
    # The account refresh rolled back with its missing event.
    assert not product.store.rows('SELECT 1 FROM users')
    assert [event['action'] for event in events(product)] == ['sign_in.refused']


ACCESS = {'sub': 'access-subject', 'issuer': 'https://synthetic.cloudflareaccess.com',
          'email': 'person@example.test', 'domain': 'example.test'}


async def test_access_sign_in_is_recorded_per_new_session_and_minute(product, tmp_path, monkeypatch):
    security = access_service(product, tmp_path)
    issued = security.access_session(request_with(), ACCESS)
    assert issued and sign_ins(product) == [
        ('sign_in.succeeded', 'person@example.test', 'cloudflare', {'method': 'cloudflare', 'enrolled': True})]
    # A valid existing session records nothing.
    cookie = SimpleCookie()
    cookie.load(issued.decode('latin-1'))
    assert security.access_session(request_with(cookie['workspace_session'].value), ACCESS) is None
    freeze_minute(monkeypatch, '2099-01-01T00:00')
    assert security.access_session(request_with(), ACCESS)
    assert sign_ins(product)[1:] == [
        ('sign_in.succeeded', 'person@example.test', 'cloudflare', {'method': 'cloudflare', 'enrolled': False})]


async def test_access_refusals_are_recorded_and_unrecorded_sign_ins_issue_no_session(product, tmp_path, monkeypatch):
    security = access_service(product, tmp_path)
    assert security.access_session(request_with(), ACCESS)
    changed = {**ACCESS, 'email': 'renamed@example.test'}
    with pytest.raises(IdentityRefused):
        security.access_session(request_with(), changed)
    assert sign_ins(product)[1:] == [
        ('sign_in.refused', 'renamed@example.test', 'cloudflare', {'method': 'cloudflare', 'reason': 'mapping_review'})]
    monkeypatch.setattr(security, 'person', lambda *args, **kwargs: None)
    connection = request_with()
    assert security.access_session(connection, ACCESS) is None
    assert not hasattr(connection.state, 'access_session')  # No session for a deactivated person.
    assert sign_ins(product)[-1] == (
        'sign_in.refused', 'person@example.test', 'cloudflare', {'method': 'cloudflare', 'reason': 'deactivated'})
    monkeypatch.undo()
    monkeypatch.setattr(sign_in_audit, 'succeeded_in', raising(DatabaseError('synthetic audit failure')))
    with pytest.raises(DatabaseError):
        security.access_session(request_with(), {**ACCESS, 'sub': 'another-subject', 'email': 'other@example.test'})


async def test_repeated_access_sign_in_events_are_written_once_per_process(product, tmp_path, monkeypatch):
    # access_actor runs for every request: a cookie-less client or a mapping in
    # review writes its per-minute event once, then only reads.
    security = access_service(product, tmp_path)
    writes = []
    for name in ('succeeded', 'record'):
        original = getattr(sign_in_audit, name)

        def counted(*args, original=original, name=name, **kwargs):
            writes.append(name)
            return original(*args, **kwargs)
        monkeypatch.setattr(sign_in_audit, name, counted)
    for _ in range(3):
        assert security.access_session(request_with(), ACCESS)
    changed = {**ACCESS, 'email': 'renamed@example.test'}
    for _ in range(3):
        with pytest.raises(IdentityRefused):
            security.access_session(request_with(), changed)
    assert writes == ['succeeded', 'record']
    assert [action for action, *_ in sign_ins(product)] == ['sign_in.succeeded', 'sign_in.refused']
    # Another process (an empty memo) repeats the write, and the key keeps one row.
    security.access_recorded.clear()
    assert security.access_session(request_with(), ACCESS)
    assert writes[-1] == 'succeeded' and len(sign_ins(product)) == 2
