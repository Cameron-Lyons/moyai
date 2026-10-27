import hashlib
import hmac
import ipaddress
import secrets
from contextlib import nullcontext
import time
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from starlette.responses import Response
from starlette.requests import HTTPConnection
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import LOOPBACK_HOSTS, Settings
from .identity_kinds import INDIVIDUAL_METHODS
from .permissions import BUILTIN_PERMISSIONS, MEMBER_PERMISSIONS, PERMISSIONS, route_permission, shared_actor_role


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def network_key(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 6 and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    # One IPv6 subscriber usually controls a whole /56.
    return str(ipaddress.ip_network(f"{address}/56", strict=False)) if address.version == 6 else str(address)


def is_proxy_peer(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


class Throttle:
    """Allow `limit` hits per key per minute, tracking at most `max_keys` keys."""

    def __init__(self, limit: int, max_keys: int = 10000):
        self.limit, self.max_keys, self.hits, self.swept = limit, max_keys, {}, time.monotonic()

    def blocked(self, key: str) -> bool:
        cutoff = time.monotonic() - 60
        if self.swept < cutoff:
            self.hits, self.swept = {k: v for k, v in self.hits.items() if v[-1] > cutoff}, time.monotonic()
        stamps = [t for t in self.hits.pop(key, []) if t > cutoff]
        if stamps:
            self.hits[key] = stamps
        return len(stamps) >= self.limit

    def record(self, key: str):
        self.hits.setdefault(key, []).append(time.monotonic())
        if len(self.hits) > self.max_keys:
            del self.hits[next(iter(self.hits))]


def local_secret(path: Path, generate) -> str:
    try:
        with path.open("x") as handle:
            path.chmod(0o600)
            handle.write(generate())
    except FileExistsError:
        pass
    return path.read_text().strip()


class Security:
    def __init__(self, settings: Settings, user_roles=None):
        self.settings = settings
        self.user_roles = user_roles
        self.secret = settings.session_secret or local_secret(settings.data_dir / "session.key", lambda: secrets.token_urlsafe(48))
        organization_id = getattr(settings, 'moyai_organization_id', '')
        if organization_id:
            # Scope the signing key itself, so explicit cursor/OAuth salts and
            # CSRF also remain isolated if operators reuse a raw session secret.
            self.secret = hmac.new(self.secret.encode(),
                ('moyai-organization-session-v1:' + organization_id).encode(), hashlib.sha256).hexdigest()
        key = settings.encryption_key or local_secret(settings.data_dir / "encryption.key", lambda: Fernet.generate_key().decode())
        self.fernet = Fernet(key.encode())
        self.signer = URLSafeTimedSerializer(self.secret, salt="workspace-session-v1")
        self.origin = settings.public_url.rstrip("/")
        self.local = urlparse(self.origin).hostname in LOOPBACK_HOSTS
        if bool(settings.google_client_id) != bool(settings.google_client_secret):
            raise ValueError("Set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
        if settings.google_enabled() and (not settings.google_domains() or not settings.google_admins()
                or any(email.rpartition("@")[2] not in settings.google_domains() for email in settings.google_admins())):
            raise ValueError("Configure GOOGLE_ALLOWED_DOMAINS and GOOGLE_ADMIN_EMAILS in those domains.")
        if not self.local and not settings.person_login_enabled() and (not settings.password_login_enabled or not settings.workspace_password):
            raise ValueError("Configure organization sign-in or WORKSPACE_PASSWORD before exposing the workspace.")
        if settings.workspace_password and len(settings.workspace_password) < 16:
            raise ValueError("Set WORKSPACE_PASSWORD to at least 16 characters before exposing the workspace.")
        if not self.local and not self.origin.startswith("https://"):
            raise ValueError("PUBLIC_URL must use HTTPS for a remote workspace.")
        if settings.workspace_member_password and (
            len(settings.workspace_member_password) < 16
            or not settings.workspace_password
            or hmac.compare_digest(settings.workspace_member_password, settings.workspace_password)
        ):
            raise ValueError("WORKSPACE_MEMBER_PASSWORD must be at least 16 characters and different from the administrator password.")

    def session_info(self, request: Request, *, connection=None) -> dict | None:
        if self.settings.cloudflare_access_login:
            # Set only by the middleware after verifying THIS request's Access
            # assertion. Cookies alone, including legacy admin cookies, cannot
            # authenticate or override the currently signed-in Access identity.
            info = getattr(request.state, 'access_session', None)
            person = self.person(info['identity']['email'], connection=connection) if info else None
            if not person:
                return None
            return {**info, **person}
        try:
            info = self.signer.loads(request.cookies.get("workspace_session", ""), max_age=43200)
            # Sessions from the original single-password deployment belong to
            # its administrator. New member sessions always carry a role/tag.
            role = info.get("role", "admin")
            if role not in {"admin", "member"} or not isinstance(info.get("sid"), str):
                return None
            method = info.get("method", "password")
            if method in {"google", "oidc"}:
                identity = info.get("identity", {})
                email = identity.get("email", "")
                if not self.signin_current(method, identity, info.get("client_id")):
                    return None
                provider = self.settings.oidc_provider_for_domain(identity["domain"]) if method == "oidc" else None
                person = self.person(email, connection=connection,
                                     require_scim=bool(provider and provider.require_scim_user))
                if not person:
                    return None
                return {**info, **person}
            elif method == "local":
                if not self.local_preview():
                    return None
            elif method != "password" or not self.settings.password_login_enabled:
                return None
            elif role == "member" and (
                not self.settings.workspace_member_password or not hmac.compare_digest(
                    info.get("password_tag", ""), digest(self.settings.workspace_member_password))
            ):
                return None
            return {**info, "role": role}
        except (BadSignature, SignatureExpired, KeyError, TypeError, AttributeError):
            return None

    def signin_current(self, method: str, identity: dict, client_id) -> bool:
        """Whether a signed Google or OIDC session still matches the live configuration.

        Each allowed domain signs in through exactly one method, so moving a
        domain to an OIDC provider ends its Google sessions, and removing or
        reconfiguring a provider ends that provider's sessions.
        """
        email, domain = identity.get("email", ""), identity.get("domain", "")
        if (not isinstance(email, str) or not isinstance(domain, str) or email.rpartition("@")[2] != domain
                or not identity.get("sub") or domain not in self.settings.google_domains()):
            return False
        if method == "google":
            return (self.settings.google_enabled() and domain in self.settings.google_signin_domains()
                    and client_id == self.settings.google_client_id)
        provider = self.settings.oidc_provider_for_domain(domain)
        return bool(provider and provider.id == identity.get("provider")
                    and identity.get("issuer") == provider.issuer and client_id == provider.client_id)

    def access_session(self, request: HTTPConnection, identity: dict) -> bytes | None:
        """Establish a browser session from a verified employee assertion only."""
        actor = self.user_roles.store.access_actor(identity)
        if actor is None:
            actor = self.user_roles.store.access_identity(identity)
        # Rechecked for every assertion and kept only on this request. Cookies
        # never provide an account id or bypass the live mapping validation.
        request.state.access_actor = actor
        try:
            info = self.signer.loads(request.cookies.get('workspace_session', ''), max_age=43200)
        except (BadSignature, SignatureExpired):
            info = {}
        if (isinstance(info, dict) and info.get('method') == 'cloudflare'
                and isinstance(info.get('sid'), str) and info['sid']
                and info.get('audience') == self.settings.cloudflare_access_audience
                and info.get('identity') == identity):
            request.state.access_session = info
            return None
        # The store pins issuer/subject to one account. Ambiguous emails and
        # attempts to rebind a different subject fail closed with ValueError.
        info = {'sid': secrets.token_urlsafe(32), 'method': 'cloudflare', 'identity': identity,
                'audience': self.settings.cloudflare_access_audience}
        request.state.access_session = info
        response = Response()
        self.set_session_cookie(response, info)
        return response.headers['set-cookie'].encode('latin-1')

    def google_role(self, email: str, *, connection=None) -> str:
        if self.user_roles is not None:
            if connection is not None:
                return self.user_roles.role_in(connection, email.strip().lower())
            return self.user_roles.role(email)
        return 'admin' if email in self.settings.google_admins() else 'member'

    def person(self, email: str, *, connection=None, require_scim=False) -> dict | None:
        """Directory status, built-in role and permissions on one connection.

        Every authorization resolves these together, so a request borrows one
        pooled connection per check rather than one for each value. None means
        the provisioned account is inactive or, with require_scim (an OIDC
        provider's require_scim_user), not provisioned and active.
        """
        if self.user_roles is None:
            return {'role': self.google_role(email)}
        email = email.strip().lower()
        with self.user_roles.store.connect() if connection is None else nullcontext(connection) as conn:
            role = self.user_roles.role_in(conn, email)
            state = self.user_roles.access_in(conn, email, role)
            if state.scim_active is False or require_scim and state.scim_active is not True:
                return None
            return {'role': role, '_permissions': state.permissions if self.user_roles.eligible(email) else frozenset()}

    def permissions_for_info(self, info):
        if not info:
            return frozenset()
        if info.get('method') in INDIVIDUAL_METHODS and self.user_roles is not None:
            if '_permissions' in info:
                return info['_permissions']  # Resolved with this session_info's role.
            return self.user_roles.permissions(info['identity']['email'])
        return BUILTIN_PERMISSIONS.get(info.get('role'), frozenset())

    def has_actor_permission(self, actor_id, permission, *, connection=None):
        if self.user_roles is None:
            return permission in BUILTIN_PERMISSIONS.get(shared_actor_role(actor_id, self.settings), frozenset())
        if connection is not None:
            return permission in self.user_roles.permissions_for_actor_in(connection, actor_id)
        with self.user_roles.store.connect() as conn:
            return permission in self.user_roles.permissions_for_actor_in(conn, actor_id)

    def local_preview(self) -> bool:
        return self.local and not self.settings.workspace_password and not self.settings.person_login_enabled()

    def session(self, request: Request) -> str | None:
        info = self.session_info(request)
        return info["sid"] if info else None

    def role(self, request: Request) -> str | None:
        info = self.session_info(request)
        return info["role"] if info else None

    def client_key(self, request: Request) -> str:
        host = request.client.host if request.client else ""
        hops = self.settings.trusted_proxy_hops
        if hops and is_proxy_peer(host):
            # Each trusted proxy appends one hop; anything further left is client-supplied.
            forwarded = [hop.strip() for line in request.headers.getlist("x-forwarded-for") for hop in line.split(",")]
            if len(forwarded) >= hops:
                host = forwarded[-hops]
        return network_key(host)

    def csrf(self, sid: str) -> str:
        return hmac.new(self.secret.encode(), f"csrf:{sid}".encode(), hashlib.sha256).hexdigest()

    def require(self, request: Request, *, mutation: bool = False, admin: bool = False,
                permission: str | None = None, connection=None, info=None) -> str:
        # Callers that already resolved this request's session_info may pass it.
        info = info if info is not None else self.session_info(request, connection=connection)
        sid = info['sid'] if info else None
        if not sid:
            raise HTTPException(401, "Sign in to the workspace.")
        required = permission or route_permission(request)
        if required is not None and required not in PERMISSIONS:
            raise ValueError('Unknown workspace permission.')
        if required and required not in self.permissions_for_info(info):
            raise HTTPException(403, 'Your workspace role does not permit this action.')
        # Existing admin endpoints receive delegated access only when their
        # concrete route has an audited permission mapping or explicit permission.
        if admin and permission is None and (required is None or required in MEMBER_PERMISSIONS) and info['role'] != "admin":
            raise HTTPException(403, "An organization administrator must perform this action.")
        if mutation:
            self.check_origin(request)
            if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), self.csrf(sid)):
                raise HTTPException(403, "Refresh the page and try again.")
        privacy = getattr(self, 'session_privacy', None)
        if privacy:
            # Reuse this synchronous admission's validated identity; subsequent
            # admissions still resolve live roles and provisioning state.
            privacy.guard_request(request, info=info)
        return sid

    def check_origin(self, request: Request):
        if request.headers.get("origin") != self.origin:
            raise HTTPException(403, "This request must come from the workspace.")

    def new_session(self, response, role: str = "admin", *, identity: dict | None = None, local: bool = False) -> str:
        sid = secrets.token_urlsafe(32)
        info = {"sid": sid, "role": role, "method": "google" if identity else "local" if local else "password"}
        if identity:
            info.update(identity=identity, client_id=self.settings.google_client_id)
        elif role == "member":
            info["password_tag"] = digest(self.settings.workspace_member_password)
        self.set_session_cookie(response, info)
        return sid

    def new_identity_session(self, response, role: str, *, method: str, identity: dict, client_id: str) -> str:
        """A session for a verified individual from an organization identity provider."""
        sid = secrets.token_urlsafe(32)
        self.set_session_cookie(response, {"sid": sid, "role": role, "method": method,
                                           "identity": identity, "client_id": client_id})
        return sid

    def set_session_cookie(self, response, info):
        response.set_cookie('workspace_session', self.signer.dumps(info), max_age=43200,
                            httponly=True, secure=not self.local, samesite='lax', path='/')

    def encrypt(self, value: str) -> str:
        return self.fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        return self.fernet.decrypt(value.encode()).decode()
