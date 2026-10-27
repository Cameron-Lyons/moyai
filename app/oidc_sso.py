"""Organization OpenID Connect sign-in (Okta, Microsoft Entra ID, other providers).

Providers are operator configuration: MOYAI_OIDC_PROVIDERS and
MOYAI_OIDC_CLIENT_SECRETS (app.config.OidcProvider). Sign-in uses the
authorization code flow with PKCE S256, a nonce, and a state bound to this
browser and to one provider. Discovery requires the exact configured issuer;
ID tokens must carry that issuer, this client as audience and authorized party,
a current expiry and issue time, an allowed asymmetric algorithm, and a
verified email in a domain this provider owns. No provider token is retained:
the verified (issuer, subject) is pinned to one account in access_identities.

Every failure redirects to /?signin=failed without echoing provider errors,
codes, tokens or claims. A refusal after a consumed state records only a fixed
reason in the governance audit.
"""
import asyncio
import base64
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Path, Request, Response
from fastapi.responses import RedirectResponse

from . import sign_in_audit
from .config import LOOPBACK_HOSTS, OIDC_PROVIDER_ID, OidcProvider
from .db import IdentityRefused
from .enterprise_roles import EMAIL
from .google_sso import SignInRedirect, SignInStart, pkce_challenge, safe_return_path, save_login_state
from .security import Throttle, digest

log = logging.getLogger(__name__)
COOKIE = 'oidc_login'
METADATA_LIMIT = 65536
TOKEN_RESPONSE_LIMIT = 262144
ID_TOKEN_LIMIT = 32768
MAX_KEYS = 100
# Key type and curve for each allowed algorithm. HMAC and 'none' never verify.
KEY_FAMILIES = {'RS256': ('RSA', None), 'PS256': ('RSA', None), 'ES256': ('EC', 'P-256')}


class OidcUnavailable(Exception):
    """Discovery or signing keys could not be loaded; never a reason to accept."""


@dataclass(frozen=True)
class Metadata:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    # RFC 9207: the provider promises an iss parameter on every authorization response.
    iss_parameter: bool


def state_digest(provider_id: str, state: str) -> str:
    """Domain-separated, so a Google state or another provider's state never matches."""
    return digest('oidc\0' + provider_id + '\0' + state)


class OidcProviderClient:
    """Discovery, signing keys, code exchange and ID token checks for one provider."""

    def __init__(self, settings, provider: OidcProvider, secret: str, *, transport=None):
        self.settings, self.provider, self.secret, self.transport = settings, provider, secret, transport
        issuer = urlsplit(provider.issuer)
        # Validated configuration allows a plain-HTTP loopback issuer only for backend tests.
        self.loopback_http = issuer.scheme == 'http' and issuer.hostname in LOOPBACK_HOSTS
        self.document: Metadata | None = None
        self.document_fetched = 0.0
        self.document_expires = 0.0
        self.document_lock = asyncio.Lock()
        self.keys: dict[str, tuple[Any, frozenset[str]]] = {}
        self.keys_expire = 0.0
        self.last_key_fetch = float('-inf')
        self.key_fetch_failed = False
        self.key_lock = asyncio.Lock()

    def endpoint(self, value) -> str:
        parsed = urlsplit(value) if isinstance(value, str) else None
        if (parsed is None or not parsed.hostname or parsed.username or parsed.password or parsed.fragment
                or not (parsed.scheme == 'https' or self.loopback_http and parsed.scheme == 'http'
                        and parsed.hostname in LOOPBACK_HOSTS)
                or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
            raise ValueError('Invalid provider endpoint')
        _ = parsed.port
        return value

    async def fetch(self, method: str, url: str, limit: int, *, timeout: float, data=None, headers=None) -> dict:
        """One JSON object; redirects, errors and oversized bodies fail. Bodies are never logged."""
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=self.transport) as client:
            async with client.stream(method, url, data=data,
                                     headers={'Accept': 'application/json', **(headers or {})}) as response:
                if response.status_code != 200 or int(response.headers.get('content-length') or 0) > limit:
                    raise ValueError('Unexpected provider response')
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > limit:
                        raise ValueError('Provider response is too large')
        try:
            value = json.loads(body)
        except RecursionError:
            raise ValueError('Provider response is too deeply nested') from None
        if not isinstance(value, dict):
            raise ValueError('Unexpected provider response')
        return value

    async def metadata(self) -> Metadata:
        now = time.monotonic()
        if self.document is not None and now < self.document_expires:
            return self.document
        async with self.document_lock:
            now = time.monotonic()
            if self.document is not None and now < self.document_expires:
                return self.document
            try:
                document = await self.fetch('GET', self.provider.issuer.rstrip('/') + '/.well-known/openid-configuration',
                                            METADATA_LIMIT, timeout=5)
                if document.get('issuer') != self.provider.issuer:
                    raise ValueError('Issuer mismatch')
                types, methods = document.get('response_types_supported'), document.get('code_challenge_methods_supported')
                if not isinstance(types, list) or 'code' not in types or (
                        methods is not None and (not isinstance(methods, list) or 'S256' not in methods)):
                    raise ValueError('Unsupported provider')
                metadata = Metadata(self.endpoint(document.get('authorization_endpoint')),
                                    self.endpoint(document.get('token_endpoint')),
                                    self.endpoint(document.get('jwks_uri')),
                                    document.get('authorization_response_iss_parameter_supported') is True)
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                # A previously verified document keeps sign-in working through a
                # short outage, for at most a day; retry about once a minute.
                if self.document is not None and now < self.document_fetched + 86400:
                    self.document_expires = now + 60
                    return self.document
                raise OidcUnavailable() from None
            self.document, self.document_fetched, self.document_expires = metadata, now, now + 3600
            return metadata

    async def signing_key(self, kid: str, alg: str):
        now = time.monotonic()
        if kid in self.keys and now < self.keys_expire:
            return self.key(kid, alg)
        async with self.key_lock:
            now = time.monotonic()
            if kid in self.keys and now < self.keys_expire:
                return self.key(kid, alg)
            # Unknown key IDs must not turn sign-in attempts into an unbounded
            # stream of requests to the identity provider. Rotation retries later.
            if now - self.last_key_fetch < 10:
                if self.key_fetch_failed or now >= self.keys_expire:
                    raise OidcUnavailable()
                raise jwt.InvalidTokenError()
            self.last_key_fetch = now
            try:
                document = await self.fetch('GET', (await self.metadata()).jwks_uri, METADATA_LIMIT, timeout=5)
                candidate = self.usable_keys(document['keys'])
            except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError, TypeError):
                self.key_fetch_failed = True
                raise OidcUnavailable() from None
            # Publish only a complete, usable set. A failed refresh must neither
            # erase known keys nor extend their original validity window.
            self.keys, self.keys_expire = candidate, time.monotonic() + 3600
            self.key_fetch_failed = False
            if kid not in self.keys:
                raise jwt.InvalidTokenError()
            return self.key(kid, alg)

    def usable_keys(self, keys) -> dict[str, tuple[Any, frozenset[str]]]:
        if not isinstance(keys, list) or len(keys) > MAX_KEYS or any(not isinstance(key, dict) for key in keys):
            raise ValueError('Invalid key set')
        candidate = {}
        for key in keys:
            # Never symmetric or private keys, encryption keys, or algorithms this provider does not allow.
            if key.get('use', 'sig') != 'sig' or 'd' in key:
                continue
            algorithms = frozenset(alg for alg in self.provider.algorithms
                                   if KEY_FAMILIES[alg] == (key.get('kty'), key.get('crv'))
                                   and key.get('alg', alg) == alg)
            if not algorithms:
                continue
            key_id = key.get('kid')
            if not isinstance(key_id, str) or not key_id or key_id in candidate:
                raise ValueError('Ambiguous key set')
            # Entra ID keys carry no 'alg'; the configured algorithm selects the type.
            public = jwt.PyJWK.from_dict(key, algorithm=min(algorithms)).key
            if key.get('kty') == 'RSA' and public.key_size < 2048:
                continue
            candidate[key_id] = (public, algorithms)
        if not candidate:
            raise ValueError('No usable signing keys')
        return candidate

    def key(self, kid: str, alg: str):
        public, algorithms = self.keys[kid]
        if alg not in algorithms:
            raise jwt.InvalidTokenError()
        return public

    async def exchange(self, code: str, verifier: str, redirect_uri: str) -> str:
        provider = self.provider
        data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri,
                'code_verifier': verifier}
        headers = {}
        if provider.token_auth == 'client_secret_post':
            data.update(client_id=provider.client_id, client_secret=self.secret)
        else:
            # RFC 6749 2.3.1: form-encode both values before HTTP Basic.
            credentials = quote_plus(provider.client_id) + ':' + quote_plus(self.secret)
            headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
        token = (await self.fetch('POST', (await self.metadata()).token_endpoint, TOKEN_RESPONSE_LIMIT,
                                  timeout=10, data=data, headers=headers)).get('id_token')
        if not isinstance(token, str) or not token or len(token) > ID_TOKEN_LIMIT:
            raise IdentityRefused('token')
        return token

    async def verify(self, token: str, nonce: str) -> dict:
        provider = self.provider
        try:
            header = jwt.get_unverified_header(token)
            alg, kid = header.get('alg'), header.get('kid')
            if alg not in provider.algorithms or not isinstance(kid, str) or not kid or len(kid) > 256:
                raise IdentityRefused('token')
            claims = jwt.decode(token, await self.signing_key(kid, alg), algorithms=[alg],
                                audience=provider.client_id, issuer=provider.issuer, leeway=60,
                                options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce']})
        except jwt.PyJWTError:
            raise IdentityRefused('token') from None
        audiences = claims['aud'] if isinstance(claims['aud'], list) else [claims['aud']]
        if (not isinstance(claims['nonce'], str) or not hmac.compare_digest(claims['nonce'], nonce)
                or claims.get('azp', provider.client_id) != provider.client_id
                or (len(audiences) > 1 and 'azp' not in claims)):
            raise IdentityRefused('token')
        subject, email = claims['sub'], claims.get(provider.email_claim)
        # ASCII before lowercasing: str.lower() maps some non-ASCII letters to
        # ASCII (KELVIN SIGN to 'k'), which would name another person's address.
        if (not isinstance(subject, str) or not 0 < len(subject) <= 255 or not isinstance(email, str)
                or len(email) > 254 or not email.isascii() or not EMAIL.fullmatch(email.lower())):
            raise IdentityRefused('claims')
        # Booleans only: a string 'true' or a missing claim is unverified.
        if claims.get(provider.email_verified_claim) is not True:
            raise IdentityRefused('email_unverified')
        email = email.lower()
        domain = email.rpartition('@')[2]
        routed = self.settings.oidc_provider_for_domain(domain)
        if (domain not in provider.domains or domain not in self.settings.google_domains()
                or routed is None or routed.id != provider.id):
            raise IdentityRefused('domain')
        name = claims['name'] if isinstance(claims.get('name'), str) else ''
        # Printable text only: control characters (NUL included) never reach the database.
        name = ' '.join(''.join(char for char in name if char.isprintable() or char.isspace()).split())[:160] or email
        return {'provider': provider.id, 'issuer': provider.issuer, 'sub': subject, 'email': email,
                'domain': domain, 'name': name}


class OidcSignIn:
    def __init__(self, settings, security, store, *, transport=None):
        self.settings, self.security, self.store = settings, security, store
        self.clients = {provider.id: OidcProviderClient(settings, provider, settings.oidc_secret(provider.id),
                                                        transport=transport)
                        for provider in settings.oidc_providers}
        self.attempts = Throttle(30)

    def options(self) -> list[dict[str, str]]:
        return [{'id': provider.id, 'label': provider.label} for provider in self.settings.oidc_providers]

    def callback(self, provider_id: str) -> str:
        return self.security.origin + f'/auth/oidc/{provider_id}/callback'

    def take_state(self, provider_id, state, browser):
        with self.store.connect() as conn:
            return conn.execute('DELETE FROM login_states WHERE state_hash=? AND browser_hash=? AND expires>? RETURNING *',
                                (state_digest(provider_id, state), digest(browser), time.time())).fetchone()

    async def verified(self, provider_id, client, row, code, error, iss):
        """The provider's verified identity for a consumed state, else IdentityRefused or OidcUnavailable."""
        if error:
            raise IdentityRefused('cancelled')
        if not code:
            raise IdentityRefused('token')
        try:
            metadata = await client.metadata()
            # RFC 9207 mix-up defense: the response must name this issuer.
            if (iss and iss != client.provider.issuer) or (not iss and metadata.iss_parameter):
                raise IdentityRefused('issuer')
            token = await client.exchange(code, row['verifier'], self.callback(provider_id))
            return await client.verify(token, row['nonce'])
        except (IdentityRefused, OidcUnavailable):
            raise
        except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError, TypeError):
            # Never echo provider errors, codes, tokens, or claims into the UI/logs.
            raise IdentityRefused('token') from None

    def admit(self, provider, identity):
        """Enroll or resolve the pinned account and its role in one writer transaction.

        A refusal rolls back the enrollment and its sign_in.succeeded event.
        """
        with self.store.connect() as conn:
            conn.begin_write()
            self.store.external_identity_in(conn, identity, kind='oidc', provider=provider.id,
                                            require_scim=provider.require_scim_user)
            person = self.security.person(identity['email'], connection=conn,
                                          require_scim=provider.require_scim_user)
            if not person:
                raise IdentityRefused('deactivated')
            return person

    def routes(self):
        router = APIRouter()

        @router.post('/api/auth/oidc/{provider}/start', operation_id='startOidcSignIn')
        async def start(body: SignInStart, request: Request, response: Response,
                        provider: str = Path(pattern=OIDC_PROVIDER_ID)) -> SignInRedirect:
            self.security.check_origin(request)
            if self.settings.cloudflare_access_login:
                self.security.require(request)
                return SignInRedirect(url='/#tasks')
            client = self.clients.get(provider)
            if client is None:
                raise HTTPException(404, 'This organization sign-in is not configured.')
            key = self.security.client_key(request)
            if self.attempts.blocked(key):
                raise HTTPException(429, 'Too many sign-in attempts. Wait a minute.')
            self.attempts.record(key)
            try:
                metadata = await client.metadata()
            except OidcUnavailable:
                raise HTTPException(503, 'Organization sign-in is temporarily unavailable. Try again shortly.') from None
            state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
            await asyncio.to_thread(save_login_state, self.store, key, state_digest(provider, state), browser,
                                    nonce, verifier, safe_return_path(body.return_to))
            params = {'client_id': client.provider.client_id, 'redirect_uri': self.callback(provider),
                      'response_type': 'code', 'scope': ' '.join(client.provider.scopes), 'state': state,
                      'nonce': nonce, 'code_challenge': pkce_challenge(verifier), 'code_challenge_method': 'S256'}
            if client.provider.prompt:
                params['prompt'] = client.provider.prompt
            # No response_mode=form_post: the callback stays a same-site GET.
            response.set_cookie(COOKIE, browser, max_age=600, httponly=True, secure=not self.security.local,
                                samesite='lax', path=f'/auth/oidc/{provider}')
            separator = '&' if urlsplit(metadata.authorization_endpoint).query else '?'
            return SignInRedirect(url=metadata.authorization_endpoint + separator + urlencode(params))

        @router.get('/auth/oidc/{provider}/callback', operation_id='completeOidcSignIn')
        async def callback(request: Request, provider: str = Path(pattern=OIDC_PROVIDER_ID), state: str = '',
                           code: str = '', error: str = '', iss: str = ''):
            cookie_path = f'/auth/oidc/{provider}'
            if self.settings.cloudflare_access_login:
                self.security.require(request)
                response = RedirectResponse('/#tasks', status_code=303)
                response.delete_cookie(COOKIE, path=cookie_path)
                return response
            client = self.clients.get(provider)
            if client is None:
                raise HTTPException(404, 'This organization sign-in is not configured.')
            if len(state) > 200 or len(code) > 8192 or len(iss) > 512:
                raise HTTPException(400, 'Invalid sign-in request.')
            browser = request.cookies.get(COOKIE, '')
            row = await asyncio.to_thread(self.take_state, provider, state, browser) if browser else None
            return_hash = row['return_path'][1:] if row else '#tasks'
            response = RedirectResponse(f"/?signin={'cancelled' if error else 'failed'}{return_hash}", status_code=303)
            response.delete_cookie(COOKIE, path=cookie_path)
            if not row:
                return response
            identity = None
            try:
                identity = await self.verified(provider, client, row, code, error, iss)
                person = await asyncio.to_thread(self.admit, client.provider, identity)
            except IdentityRefused as refused:
                reason = refused.reason
            except OidcUnavailable:
                reason = 'unavailable'
            except Exception as failure:
                # A database or other unexpected failure still fails closed with
                # the same redirect. Log only its type: it may carry claims.
                log.warning('Organization sign-in failed: %s', type(failure).__name__)
                reason = 'unavailable'
            else:
                response = RedirectResponse(row['return_path'], status_code=303)
                response.delete_cookie(COOKIE, path=cookie_path)
                self.security.new_session(response, person['role'], identity=identity, method='oidc',
                                          client_id=client.provider.client_id)
                return response
            # Only a fully verified identity names the actor (any refusal after
            # verification); claims alone do not.
            try:
                await asyncio.to_thread(sign_in_audit.refused, self.store, 'oidc', reason,
                                        email=identity['email'] if identity else '', client=row['client'],
                                        resource_id=provider)
            except Exception as failure:
                log.warning('Organization sign-in refusal was not recorded: %s', type(failure).__name__)
            return response

        return router
