"""Service accounts and their API keys, for unattended read-only programmatic access.

A service account is a canonical governance object, not a person: it has no row
in users, user_roles, access_identities, scim_users or the native users table,
so people listings, SCIM, administrator counts and per-email spend never see it.
Its sorted permission list stays inside permissions.SERVICE_PERMISSIONS, and
verification intersects it with that ceiling again, so narrowing the ceiling
revokes at once. Keys reach only permissions.API_KEY_ROUTES.

Keys look like moyai_sk_<key id>.<secret>, are shown once and stored only as
SHA-256 (the secret has 256 bits, so no key derivation is needed). A key is
found by its id, never its hash, and the hash is compared in constant time.

Holders of service_accounts.manage list accounts, revoke keys and disable
accounts, which only narrows access. Creating or changing an account,
re-enabling it and issuing keys need a built-in administrator, as SCIM tokens
do: a key is a standing credential that outlives its issuer's role. Each change
records one governance audit event, never with tokens or hashes.

access_revision only increases (permission changes, disable, enable) and is part
of every key's authority entry, so narrowing and widening again never revives a
saved grant. Disabling revokes every key; enabling never restores them. Last use
(scim.record_use) is best-effort bookkeeping, never an authorization input.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enterprise_roles import (
    STALE,
    GovernanceConflict,
    GovernanceForbidden,
    GovernanceNotFound,
    role_permissions,
    validated,
)
from .governance_audit import recent_in, record_event_in, timestamp
from .permissions import API_KEY_ROUTES, SERVICE_PERMISSIONS
from .schema_initializers import initialize_service_accounts as initialize_schema
from .scim import record_use, stale_use, valid_text
from .security import digest

PREFIX = 'moyai_sk_'
KEY = re.compile(r'(?i:bearer)[ \t]+(moyai_sk_([0-9a-f]{32})\.[A-Za-z0-9_-]{43})')
PRINCIPAL = re.compile(r'service:([0-9a-f]{32}):([0-9a-f]{32})')
PRINCIPAL_PREFIX = 'service:'
UNAUTHENTICATED = 'A valid API key is required.'
REFUSED_ROUTE = 'API keys cannot access this endpoint.'
# Every key expires; there is no unlimited choice.
ExpiryDays = Literal[30, 90, 180, 365]
MAX_ACTIVE_KEYS = 5
MAX_ACCOUNTS = 100  # Active accounts; disabled accounts cannot authenticate and do not count.
ADMIN_ONLY = 'Only a built-in administrator can create service accounts, change their access or issue API keys.'
# One read by key id, shared by canonical code and the native async reader.
# Format {keys} and {accounts} with the (qualified) table names.
KEY_QUERY = ('SELECT k.id,k.account_id,k.token_hash,k.prefix,k.expires_at,k.last_used_at,k.revoked_at,'
             'a.name,a.permissions,a.access_revision,a.active '
             'FROM {keys} k JOIN {accounts} a ON a.id=k.account_id WHERE k.id=:key_id')
# What a key's record shows; never token_hash.
KEY_COLUMNS = ('id,account_id,label,prefix,created_at,created_by,expires_at,last_used_at,last_used_from,'
               'revoked_at,revoked_by')


def presented(header) -> bool:
    """Whether an Authorization value offers an API key, well formed or not.

    No database work. Anything mentioning the key prefix must then verify as a
    key or be refused; it never falls back to cookie authentication.
    """
    return isinstance(header, str) and PREFIX in header.lower()


def parse(header) -> tuple[str, str]:
    """(key id, token) from a Bearer header; a malformed value is 401 before any connection opens."""
    match = KEY.fullmatch(header) if isinstance(header, str) else None
    if match is None:
        raise HTTPException(401, UNAUTHENTICATED, headers={'WWW-Authenticate': 'Bearer'})
    return match[2], match[1]


def logged_prefix(header) -> str:
    """The key prefix (moyai_sk_ plus 8 hex) of a well-formed Bearer header for logs, else ''.

    Only a full match of the key format yields a prefix, so a log line never
    carries any other part of the header.
    """
    match = KEY.fullmatch(header) if isinstance(header, str) else None
    return match[1][:len(PREFIX) + 8] if match else ''


def is_principal_id(value) -> bool:
    """Whether a principal id names a service account key; such ids never name people."""
    return isinstance(value, str) and value.startswith(PRINCIPAL_PREFIX)


def mint() -> tuple[str, str, str]:
    """(key id, token, prefix) for a new key; the prefix is moyai_sk_ plus 8 hex."""
    identity = uuid4().hex
    token = PREFIX + identity + '.' + secrets.token_urlsafe(32)
    return identity, token, token[:len(PREFIX) + 8]


def parse_principal_id(value) -> tuple[str, str] | None:
    """(account id, key id) of a service principal id, else None."""
    match = PRINCIPAL.fullmatch(value) if isinstance(value, str) else None
    return (match[1], match[2]) if match else None


def _instant(value) -> datetime | None:
    try:
        instant = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return instant.replace(tzinfo=UTC) if instant.tzinfo is None else instant


@dataclass(frozen=True)
class ServiceKeyAuthority:
    """A verified, unexpired, unrevoked key of an active account."""
    account: str
    key: str
    name: str
    prefix: str
    access_revision: int
    permissions: frozenset[str]
    expires_at: str
    last_used_at: str

    @property
    def principal_id(self) -> str:
        return f'{PRINCIPAL_PREFIX}{self.account}:{self.key}'

    def authority_entry(self) -> dict[str, Any]:
        """What a saved grant depends on; the native adapter HMACs it into the authority version."""
        return {'kind': 'service', 'account': self.account, 'key': self.key,
                'access_revision': self.access_revision, 'permissions': sorted(self.permissions),
                'expires_at': self.expires_at}


def verify(row, token: str | None = None, account_id: str | None = None,
           now: datetime | None = None) -> ServiceKeyAuthority | None:
    """The key's authority from a KEY_QUERY row, or None. Fails closed on anything unexpected.

    Pass exactly one of token, the presented key (hash compared in constant
    time), or account_id, the account a saved grant's principal id names.
    TypeError otherwise: a check with neither would accept any live row.
    """
    if (token is None) == (account_id is None):
        raise TypeError('Verify a service key with exactly one of token and account_id.')
    presented_hash = digest(token) if token is not None else ''
    if row is None:
        return None
    if token is not None and not hmac.compare_digest(str(row['token_hash']), presented_hash):
        return None
    if row['revoked_at'] != '' or row['active'] != 1:
        return None
    if account_id is not None and row['account_id'] != account_id:
        return None
    expires = _instant(row['expires_at'])
    if expires is None or expires <= (now or datetime.now(UTC)):
        return None
    return ServiceKeyAuthority(
        account=row['account_id'], key=row['id'], name=row['name'], prefix=row['prefix'],
        access_revision=int(row['access_revision']),
        permissions=role_permissions(row['permissions']) & SERVICE_PERMISSIONS,
        expires_at=row['expires_at'], last_used_at=row['last_used_at'])


def key_row_in(conn, key_id: str):
    """KEY_QUERY on a canonical Store connection."""
    query = KEY_QUERY.format(keys='service_account_keys', accounts='service_accounts')
    return conn.execute(query.replace(':key_id', '?'), (key_id,)).fetchone()


def _text(value: str) -> str:
    # PostgreSQL rejects NUL and the drivers cannot encode lone surrogates.
    if not valid_text(value):
        raise ValueError('Text cannot contain NUL characters or invalid Unicode.')
    return value


def _ceiling(values: list[str]) -> list[str]:
    if any(value not in SERVICE_PERMISSIONS for value in values):
        raise ValueError(f"Service accounts may hold only {' and '.join(sorted(SERVICE_PERMISSIONS))}.")
    if not values:
        raise ValueError('Choose at least one permission.')
    return sorted(set(values))


class ServiceAccountCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default='', max_length=500)
    permissions: list[str] = Field(max_length=10)

    _text = field_validator('name', 'description')(_text)
    _permissions = field_validator('permissions')(_ceiling)


class ServiceAccountUpdate(ServiceAccountCreate):
    """The complete account at the revision the editor showed; active false disables it."""
    active: bool
    revision: int = Field(ge=1)


class ServiceKeyCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    label: str = Field(min_length=1, max_length=80)
    expires_in_days: ExpiryDays = 90

    _text = field_validator('label')(_text)


def _status(row, now: datetime) -> str:
    if row['revoked_at']:
        return 'revoked'
    expires = _instant(row['expires_at'])
    return 'expired' if expires is None or expires <= now else 'active'


def _key_view(row, now: datetime) -> dict[str, Any]:
    return {'id': row['id'], 'account_id': row['account_id'], 'label': row['label'], 'prefix': row['prefix'],
            'created_at': row['created_at'], 'created_by': row['created_by'], 'expires_at': row['expires_at'],
            'last_used_at': row['last_used_at'] or None, 'last_used_from': row['last_used_from'] or None,
            'revoked_at': row['revoked_at'] or None, 'revoked_by': row['revoked_by'] or None,
            'status': _status(row, now)}


def _permissions(row) -> list[str]:
    return sorted(role_permissions(row['permissions']) & SERVICE_PERMISSIONS)


def _account_view(row, keys) -> dict[str, Any]:
    return {'id': row['id'], 'name': row['name'], 'description': row['description'],
            'permissions': _permissions(row), 'revision': int(row['revision']), 'active': row['active'] == 1,
            'created_at': row['created_at'], 'created_by': row['created_by'],
            'updated_at': row['updated_at'], 'updated_by': row['updated_by'], 'keys': keys}


def _json(values: list[str]) -> str:
    return json.dumps(sorted(values))


class ServiceAccounts:
    """Service account and API key administration over a canonical Store.

    user_roles supplies the enterprise role resolver. Methods are synchronous;
    native routes call them through asyncio.to_thread. actor is a
    GovernanceActor or a ProductPrincipal; service principals are refused.
    """

    def __init__(self, store, user_roles):
        self.store, self.roles = store, user_roles
        if store.schema_updates:
            initialize_schema(store)

    # Reads

    def listing(self, actor) -> dict[str, Any]:
        """GET /api/admin/service-accounts; service_accounts.manage."""
        now = datetime.now(UTC)
        with self.store.connect() as conn:
            conn.begin_read()
            authority = self.roles.enterprise.authorize_in(conn, actor, 'service_accounts.manage')
            keys: dict[str, list[dict[str, Any]]] = {}
            for row in conn.execute(f'SELECT {KEY_COLUMNS} FROM service_account_keys ORDER BY created_at DESC,id DESC'):
                keys.setdefault(row['account_id'], []).append(_key_view(row, now))
            accounts = [_account_view(row, keys.get(row['id'], []))
                        for row in conn.execute('SELECT * FROM service_accounts ORDER BY name_key,id')]
            activity = recent_in(conn, self.store.database, ('service_account', 'service_account_key'))
        return {'accounts': accounts, 'permission_ceiling': sorted(SERVICE_PERMISSIONS),
                'key_routes': [{'method': method, 'path': path, 'permission': permission}
                               for (method, path), permission in API_KEY_ROUTES.items()],
                'max_active_keys': MAX_ACTIVE_KEYS, 'can_create': authority.builtin_admin, 'activity': activity}

    def _view_in(self, conn, account_id: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        row = conn.execute('SELECT * FROM service_accounts WHERE id=?', (account_id,)).fetchone()
        keys = [_key_view(key, now) for key in conn.execute(
            f'SELECT {KEY_COLUMNS} FROM service_account_keys WHERE account_id=? ORDER BY created_at DESC,id DESC',
            (account_id,))]
        return _account_view(row, keys)

    # Writers

    def _admin_in(self, conn, actor):
        authority = self.roles.enterprise.authority_in(conn, actor)
        if not authority.builtin_admin:
            raise GovernanceForbidden(ADMIN_ONLY)
        return authority

    @staticmethod
    def _account_in(conn, account_id: str):
        row = conn.execute('SELECT * FROM service_accounts WHERE id=?', (account_id,)).fetchone()
        if row is None:
            raise GovernanceNotFound('Service account not found.')
        return row

    @staticmethod
    def _unique_name_in(conn, name: str, account_id: str = '') -> str:
        key = name.casefold()
        if conn.execute('SELECT 1 FROM service_accounts WHERE name_key=? AND id<>?', (key, account_id)).fetchone():
            raise GovernanceConflict('A service account with this name already exists.')
        return key

    @staticmethod
    def _revoke_all_in(conn, account_id: str, stamp: str) -> dict[str, Any]:
        """Revoke every unrevoked key of a disabled account, expired ones included.

        Details for service_account.disabled: revoked_keys lists, oldest first,
        the prefixes of keys that were still usable, so at most MAX_ACTIVE_KEYS
        however many expired keys were never revoked; revoked_count counts
        every key this marked revoked.
        """
        usable = conn.execute('''SELECT prefix FROM service_account_keys WHERE account_id=? AND revoked_at=''
            AND expires_at>? ORDER BY created_at,id''', (account_id, stamp)).fetchall()
        revoked = conn.execute('''UPDATE service_account_keys SET revoked_at=?,revoked_by='service_account.disabled'
            WHERE revoked_at='' AND account_id=?''', (stamp, account_id)).rowcount
        return {'revoked_keys': [row['prefix'] for row in usable], 'revoked_count': revoked}

    @staticmethod
    def _account_room_in(conn) -> None:
        active = conn.execute('SELECT COUNT(*) AS total FROM service_accounts WHERE active=1').fetchone()['total']
        if active >= MAX_ACCOUNTS:
            raise GovernanceConflict(f'A workspace can have at most {MAX_ACCOUNTS} active service accounts. '
                                     'Disable one first.')

    def create(self, body: ServiceAccountCreate, actor) -> dict[str, Any]:
        body = validated(ServiceAccountCreate, body)
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self._admin_in(conn, actor)
            self._account_room_in(conn)
            name_key = self._unique_name_in(conn, body.name)
            identity, stamp = uuid4().hex, timestamp()
            conn.execute('''INSERT INTO service_accounts(id,name,name_key,description,permissions,revision,
                access_revision,active,created_by,created_at,updated_by,updated_at) VALUES(?,?,?,?,?,1,1,1,?,?,?,?)''',
                (identity, body.name, name_key, body.description, _json(body.permissions),
                 authority.label, stamp, authority.label, stamp))
            record_event_in(conn, 'service_account.created', authority.label, 'service_account', identity,
                            {'name': body.name, 'permissions': body.permissions})
            return self._view_in(conn, identity)

    def update(self, account_id: str, body: ServiceAccountUpdate, actor) -> dict[str, Any]:
        """Replace the name, description, permissions and active state at the shown revision.

        Built-in administrators only, since this can widen access. An unchanged
        update records nothing. Deactivating revokes every key and records the
        same service_account.disabled details as disable, with the permission
        fields only when they changed too; enabling records service_account.enabled.
        """
        body = validated(ServiceAccountUpdate, body)
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self._admin_in(conn, actor)
            row = self._account_in(conn, account_id)
            if int(row['revision']) != body.revision:
                raise GovernanceConflict(STALE)
            previous, was_active = _permissions(row), row['active'] == 1
            if (body.name, body.description, body.permissions, body.active) == (
                    row['name'], row['description'], previous, was_active):
                return self._view_in(conn, account_id)
            name_key = self._unique_name_in(conn, body.name, account_id)
            if body.active and not was_active:
                self._account_room_in(conn)
            access = body.permissions != previous or body.active != was_active
            stamp = timestamp()
            conn.execute('''UPDATE service_accounts SET name=?,name_key=?,description=?,permissions=?,active=?,
                revision=revision+1,access_revision=access_revision+?,updated_by=?,updated_at=? WHERE id=?''',
                (body.name, name_key, body.description, _json(body.permissions), int(body.active), int(access),
                 authority.label, stamp, account_id))
            changed = {'permissions': body.permissions, 'previous_permissions': previous}
            if body.active == was_active:
                action, details = 'service_account.updated', {'name': body.name, **changed, 'active': body.active}
            else:
                # The same details as disable and enable, plus permissions only when they changed as well.
                details = {'name': body.name, **(changed if body.permissions != previous else {})}
                action = 'service_account.enabled' if body.active else 'service_account.disabled'
                if not body.active:
                    details |= self._revoke_all_in(conn, account_id, stamp)
            record_event_in(conn, action, authority.label, 'service_account', account_id, details)
            return self._view_in(conn, account_id)

    def disable(self, account_id: str, revision: int, actor) -> dict[str, Any]:
        """Disable an account and revoke all its keys; service_accounts.manage. A disabled account is a no-op."""
        if type(revision) is not int:
            raise TypeError('Service account revisions are integers.')
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self.roles.enterprise.authorize_in(conn, actor, 'service_accounts.manage')
            row = self._account_in(conn, account_id)
            if int(row['revision']) != revision:
                raise GovernanceConflict(STALE)
            if row['active'] != 1:
                return self._view_in(conn, account_id)
            stamp = timestamp()
            conn.execute('''UPDATE service_accounts SET active=0,revision=revision+1,access_revision=access_revision+1,
                updated_by=?,updated_at=? WHERE id=?''', (authority.label, stamp, account_id))
            record_event_in(conn, 'service_account.disabled', authority.label, 'service_account', account_id,
                            {'name': row['name'], **self._revoke_all_in(conn, account_id, stamp)})
            return self._view_in(conn, account_id)

    def create_key(self, account_id: str, body: ServiceKeyCreate, actor) -> tuple[dict[str, Any], str]:
        """(key record, token). The token is returned only here and stored as SHA-256."""
        body = validated(ServiceKeyCreate, body)
        identity, token, prefix = mint()
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self._admin_in(conn, actor)
            account = self._account_in(conn, account_id)
            if account['active'] != 1:
                raise GovernanceConflict('Enable this service account before issuing a key.')
            created = datetime.now(UTC)
            stamp = created.isoformat(timespec='microseconds')
            # Expired keys no longer count; every writer stores this fixed-width UTC spelling.
            usable = conn.execute('''SELECT COUNT(*) AS total FROM service_account_keys
                WHERE account_id=? AND revoked_at='' AND expires_at>?''', (account_id, stamp)).fetchone()['total']
            if usable >= MAX_ACTIVE_KEYS:
                raise GovernanceConflict(f'A service account can have at most {MAX_ACTIVE_KEYS} active keys. '
                                         'Revoke one first.')
            expires = (created + timedelta(days=body.expires_in_days)).isoformat(timespec='microseconds')
            conn.execute('''INSERT INTO service_account_keys(id,account_id,label,token_hash,prefix,created_by,created_at,
                expires_at,last_used_at,last_used_from,revoked_at,revoked_by) VALUES(?,?,?,?,?,?,?,?,'','','','')''',
                (identity, account_id, body.label, digest(token), prefix, authority.label, stamp, expires))
            record_event_in(conn, 'service_account_key.created', authority.label, 'service_account_key', identity,
                            {'account_id': account_id, 'label': body.label, 'prefix': prefix, 'expires_at': expires})
            row = conn.execute(f'SELECT {KEY_COLUMNS} FROM service_account_keys WHERE id=?', (identity,)).fetchone()
        return _key_view(row, created), token

    def revoke_key(self, account_id: str, key_id: str, actor) -> dict[str, Any]:
        """Revoke a key (idempotent) and return its record; service_accounts.manage."""
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self.roles.enterprise.authorize_in(conn, actor, 'service_accounts.manage')
            row = conn.execute(f'SELECT {KEY_COLUMNS} FROM service_account_keys WHERE id=? AND account_id=?',
                               (key_id, account_id)).fetchone()
            if row is None:
                raise GovernanceNotFound('API key not found.')
            if not row['revoked_at']:
                row = {**dict(row), 'revoked_at': timestamp(), 'revoked_by': authority.label}
                conn.execute('UPDATE service_account_keys SET revoked_at=?,revoked_by=? WHERE id=?',
                             (row['revoked_at'], row['revoked_by'], key_id))
                record_event_in(conn, 'service_account_key.revoked', authority.label, 'service_account_key', key_id,
                                {'account_id': account_id, 'label': row['label'], 'prefix': row['prefix']})
        return _key_view(row, datetime.now(UTC))

    def touch(self, key_id: str, last_used_at: str, network: str) -> None:
        """Record use and network at most once per interval; never for a revoked key. See scim.record_use."""
        if stale_use(last_used_at):
            record_use(self.store, 'service_account_keys', 'service-key-use', key_id,
                       {'last_used_from': (network or '')[:100]}, what='API key')
