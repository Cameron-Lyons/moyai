"""Custom workspace roles, direct email assignments and directory-group grants.

Built-in admin/member roles remain in user_roles. Effective permissions are
(the direct custom role, or the built-in set) ∪ live directory-group grants; a
built-in admin always holds every permission, an archived direct role grants
nothing (never the member default), and a SCIM-deactivated or deleted person
holds nothing. A direct 'member' assignment row is equivalent to no row.

resolve_access is pure: it reads through fetch(name, params) over
ACCESS_QUERIES, so canonical connections (canonical_fetch) and the native
identity adapter's async snapshot (qualified_fetch) share one rule set.

Delegation never amplifies. Anyone other than a built-in administrator may
grant, change or remove only access whose permissions they hold directly
(group-derived permissions are excluded), may not change their own access, the
grants of groups they belong to, or the definition of a role that reaches them
directly or through such a group, and never grants or removes administrator
access. Writers take the canonical exclusive writer, re-resolve the actor inside
that transaction, and record exactly one governance audit event per change.

Authority entries are monotonic: once governance has touched a person (any
assignment row, including 'member', or a SCIM deactivation, deletion or loss of a
granted group), returning to default access never restores an earlier entry,
so saved authority versions stay revoked. People governance never touched keep
no entry, so upgrading leaves their authority versions unchanged.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .governance_audit import record_event_in, timestamp
from .permissions import BUILTIN_PERMISSIONS, MEMBER_PERMISSIONS, PERMISSIONS, shared_actor_role
from .schema_initializers import initialize_enterprise_roles as initialize_schema

ALL_PERMISSIONS = BUILTIN_PERMISSIONS['admin']
ROLE_ID = r'^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$'
GROUP_ID = re.compile(r'[0-9a-f]{32}')
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+")

STALE = 'This changed elsewhere. Reload and try again.'
FORBIDDEN = 'Your workspace role does not allow this action.'
DEACTIVATED = 'This workspace account has been deactivated.'
ADMIN_ONLY = 'Only a built-in administrator can grant or remove administrator access.'
AMPLIFY = 'You can only grant permissions you hold.'
HELD_ROLE = 'You can only change a role whose permissions you hold.'
HELD_PERSON = 'You can only change access for people whose permissions you hold.'
HELD_GRANT = 'You can only change a group grant whose permissions you hold.'
SELF = 'You cannot change your own access.'
OWN_GROUP = 'You cannot change grants for a group you belong to.'
INELIGIBLE = 'Use an email in the workspace’s allowed domains.'


class GovernanceError(HTTPException):
    """A typed governance refusal; status_code maps directly to the HTTP response."""
    status = 400

    def __init__(self, detail: str):
        super().__init__(self.status, detail)


class GovernanceUnauthenticated(GovernanceError):
    status = 401


class GovernanceForbidden(GovernanceError):
    status = 403


class GovernanceNotFound(GovernanceError):
    status = 404


class GovernanceConflict(GovernanceError):
    """Stale revisions use exactly STALE; other conflicts explain themselves."""
    status = 409


class GovernanceInvalid(GovernanceError):
    status = 422


def normalized_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL.fullmatch(value):
        raise ValueError('Enter a work email address.')
    return value


def role_permissions(document) -> frozenset[str]:
    """Catalog permissions in a stored JSON list; anything malformed grants nothing."""
    try:
        values = json.loads(document)
    except (TypeError, ValueError):
        return frozenset()
    if not isinstance(values, list):
        return frozenset()
    return frozenset(value for value in values if isinstance(value, str) and value in PERMISSIONS)


def known_permissions(values: list[str]) -> list[str]:
    if any(value not in PERMISSIONS for value in values):
        raise ValueError('Choose permissions from the workspace permission catalog.')
    return sorted(set(values))


class RoleCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    id: str = Field(pattern=ROLE_ID, max_length=64)
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default='', max_length=500)
    permissions: list[str] = Field(default_factory=list, max_length=200)

    @field_validator('id')
    @classmethod
    def custom_id(cls, value):
        if value in BUILTIN_PERMISSIONS:
            raise ValueError('Built-in roles cannot be edited.')
        return value

    _permissions = field_validator('permissions')(known_permissions)


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default='', max_length=500)
    permissions: list[str] = Field(default_factory=list, max_length=200)
    revision: int = Field(ge=0)

    _permissions = field_validator('permissions')(known_permissions)


class RoleAssignment(BaseModel):
    """role_id 'member' removes a custom role. role_revision is the user_roles revision shown, if any."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    role_id: str = Field(min_length=1, max_length=64)
    revision: int = Field(default=0, ge=0)
    role_revision: int | None = Field(default=None, ge=0)

    _email = field_validator('email')(normalized_email)


class GroupRoleChange(BaseModel):
    """role_id None clears the group's grant."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    role_id: str | None = Field(default=None, min_length=1, max_length=64)
    revision: int = Field(default=0, ge=0)


# Named parameters and {table} placeholders; canonical_fetch and qualified_fetch adapt them.
ACCESS_TABLES = ('user_roles', 'scim_users', 'scim_groups', 'scim_group_members',
                 'enterprise_roles', 'enterprise_role_assignments', 'enterprise_group_roles')
ACCESS_QUERIES = {
    # A live row wins over tombstones, then the latest update (idx_scim_users_lookup).
    'scim_user': ("SELECT id, active, deleted_at, access_epoch FROM {scim_users} WHERE user_name=:email "
                  "ORDER BY (deleted_at='') DESC, updated_at DESC LIMIT 1"),
    'assignment': 'SELECT role_id, revision FROM {enterprise_role_assignments} WHERE email=:email',
    'role': 'SELECT id, name, permissions, revision, archived FROM {enterprise_roles} WHERE id=:role_id',
    'group_grants': '''SELECT r.group_id, r.revision, r.role_id, e.permissions, e.archived,
            e.revision AS role_revision
        FROM {enterprise_group_roles} r
        JOIN {scim_groups} g ON g.id=r.group_id AND g.deleted_at=''
        JOIN {scim_group_members} m ON m.group_id=g.id
        JOIN {scim_users} u ON u.id=m.user_id AND u.deleted_at='' AND u.active=1
        LEFT JOIN {enterprise_roles} e ON e.id=r.role_id
        WHERE u.user_name=:email AND r.role_id IS NOT NULL ORDER BY r.group_id''',
}
NAMED = re.compile(r'(?<![:\w]):([a-z_]+)\b')

Fetch = Callable[[str, Mapping[str, Any]], Iterable[Mapping[str, Any]]]


def qualified_queries(table: Callable[[str], str]) -> dict[str, str]:
    """ACCESS_QUERIES with each {name} replaced by table(name); :named parameters remain."""
    names = {name: table(name) for name in ACCESS_TABLES}
    return {key: sql.format(**names) for key, sql in ACCESS_QUERIES.items()}


def qualified_fetch(execute: Callable[[str, dict[str, Any]], Iterable[Mapping[str, Any]]],
                    table: Callable[[str], str]) -> Fetch:
    """A resolve_access fetch over named-parameter SQL and qualified table names.

    execute(sql, params) runs one read and returns mapping rows. The native
    identity adapter runs it inside its own REPEATABLE READ snapshot, e.g. under
    AsyncSession.run_sync with
    `lambda sql, params: session.execute(text(sql), params).mappings().all()`
    and its schema-qualified, quoted `_table`.
    """
    queries = qualified_queries(table)
    return lambda name, params: list(execute(queries[name], dict(params)))


@cache
def _positional(name: str) -> tuple[str, tuple[str, ...]]:
    sql = ACCESS_QUERIES[name].format(**{table: table for table in ACCESS_TABLES})
    return NAMED.sub('?', sql), tuple(NAMED.findall(sql))


def canonical_fetch(conn) -> Fetch:
    """A resolve_access fetch on a canonical Store connection (qmark bindings, search_path tables)."""
    def fetch(name, params):
        sql, order = _positional(name)
        return [dict(row) for row in conn.execute(sql, tuple(params[key] for key in order)).fetchall()]
    return fetch


def _first(rows):
    for row in rows:
        return row
    return None


@dataclass(frozen=True)
class AccessState:
    """One person's governance state.

    role_id/role_name: the direct custom role (None without one, or with a
    built-in 'member' row). assignment_revision: the enterprise_role_assignments
    revision (0 without a row). role_revision: the direct custom role
    definition's revision (0 without one); unlike the roles API's
    role_revision, it is not the user_roles revision. groups: (group_id, grant
    revision, role_id) for every grant applying through live SCIM membership.
    scim_active: None when the email is not SCIM-managed, False when deactivated
    or deleted. default: no custom role and permissions equal the built-in set;
    Slack treats such an email as ungoverned. grant_roles: sorted (role_id, role
    definition revision) of the granted roles, so narrowing and re-widening a
    granted role is never the same state. directory: (SCIM user id, access epoch)
    once the directory has narrowed this email's access (deactivation, deletion,
    reprovisioning a deleted userName, or leaving a granted group); None before.

    Authority versions must use authority_entry(), never default alone: a
    default state with history still has an entry.
    """
    permissions: frozenset[str]
    role_id: str | None
    role_name: str | None
    assignment_revision: int
    role_revision: int
    groups: tuple[tuple[str, int, str | None], ...]
    scim_active: bool | None
    default: bool
    direct_permissions: frozenset[str] = frozenset()
    grant_roles: tuple[tuple[str, int], ...] = ()
    directory: tuple[str, int] | None = None

    def authority_entry(self) -> dict[str, Any] | None:
        """The bounded authority-version entry, monotonic across governance changes.

        None only for default state that governance never touched, which must
        not change upgraded authority versions. An assignment row (even a reset
        to 'member') keeps its revision and directory history keeps the SCIM id
        and access epoch, so returning to default never revalidates an earlier
        version.
        """
        if self.default and not self.assignment_revision and self.directory is None:
            return None
        entry: dict[str, Any] = {
            'role_id': self.role_id, 'role_revision': self.role_revision,
            'assignment_revision': self.assignment_revision,
            'groups': [list(group) for group in self.groups], 'permissions': sorted(self.permissions)}
        if self.grant_roles:
            entry['grant_roles'] = [list(item) for item in self.grant_roles]
        if self.directory is not None:
            entry['directory'] = list(self.directory)
        return entry


def resolve_access(fetch: Fetch, email: str, builtin_role: str) -> AccessState:
    """Effective governance state for a normalized email whose built-in role is already resolved."""
    if builtin_role not in BUILTIN_PERMISSIONS:
        raise ValueError('Unknown built-in role.')
    scim = _first(fetch('scim_user', {'email': email}))
    scim_active = None if scim is None else bool(scim['active'] and not scim['deleted_at'])
    # Provisioning alone leaves no history; deactivation, deletion and leaving
    # a granted group advance the epoch, and a new id replaces a deleted one.
    directory = None if scim is None or (scim_active and not int(scim['access_epoch'])) else (
        str(scim['id']), int(scim['access_epoch']))
    assignment = _first(fetch('assignment', {'email': email}))
    assignment_revision = int(assignment['revision']) if assignment else 0
    role_id = assignment['role_id'] if assignment and assignment['role_id'] != 'member' else None
    role_name, role_revision = None, 0
    if role_id is None:
        direct = BUILTIN_PERMISSIONS[builtin_role]
    else:
        role = None if role_id in BUILTIN_PERMISSIONS else _first(fetch('role', {'role_id': role_id}))
        # An archived, missing or built-in-named assigned role grants nothing,
        # never the member default.
        direct = role_permissions(role['permissions']) if role and not role['archived'] else frozenset()
        if role:
            role_name, role_revision = role['name'], int(role['revision'])
    groups, granted, grant_roles = [], set(), set()
    if scim_active:  # Group grants apply only through a live, active SCIM user.
        for row in fetch('group_grants', {'email': email}):
            groups.append((row['group_id'], int(row['revision']), row['role_id']))
            if row['role_revision'] is not None:
                grant_roles.add((row['role_id'], int(row['role_revision'])))
            if row['permissions'] is not None and not row['archived'] and row['role_id'] not in BUILTIN_PERMISSIONS:
                granted |= role_permissions(row['permissions'])
    if builtin_role == 'admin':
        direct = ALL_PERMISSIONS
    if scim_active is False:
        permissions = frozenset()
    else:
        permissions = ALL_PERMISSIONS if builtin_role == 'admin' else direct | granted
    return AccessState(
        permissions=frozenset(permissions), role_id=role_id, role_name=role_name,
        assignment_revision=assignment_revision, role_revision=role_revision, groups=tuple(groups),
        scim_active=scim_active,
        default=role_id is None and scim_active is not False and permissions == BUILTIN_PERMISSIONS[builtin_role],
        direct_permissions=frozenset() if scim_active is False else frozenset(direct),
        grant_roles=tuple(sorted(grant_roles)), directory=directory,
    )


def narrow_group_in(conn, group_id: str) -> None:
    """Advance the access epoch of a group's members when its role grant ends.

    Losing a last grant can otherwise return an authority entry to None and
    revalidate a version issued before the grant.
    """
    conn.execute('''UPDATE scim_users SET access_epoch=access_epoch+1
        WHERE id IN (SELECT user_id FROM scim_group_members WHERE group_id=?)''', (group_id,))


def scim_state_in(conn, email: str) -> bool | None:
    """None when unmanaged, else whether the email's SCIM account is live and active."""
    row = _first(canonical_fetch(conn)('scim_user', {'email': email.strip().lower()}))
    return None if row is None else bool(row['active'] and not row['deleted_at'])


@dataclass(frozen=True)
class GovernanceActor:
    """Who performs a governance change, as authenticated by the HTTP layer.

    id: the principal id (`google:<sub>`, a canonical users id, or
    `shared:<local|password>:<role>`). email: the individual's email; empty
    for shared actors. builtin_role: 'admin' or 'member' as authenticated, or
    None for no claim (legacy session dicts, whose role was already derived
    from the canonical role). permissions: the principal's effective
    permissions, or None when the caller has no snapshot. direct_permissions: directly held
    permissions, or None to rely on in-transaction resolution. kind:
    'individual' (verified Google/Access person), 'shared', or another principal
    kind, which is refused; empty infers it from id.

    Services never trust these alone. Each operation re-resolves the actor's
    built-in role, SCIM state and permissions inside its own transaction and
    uses the intersection, so a stale actor can only lose authority.
    """
    id: str
    email: str = ''
    builtin_role: str | None = 'member'
    permissions: frozenset[str] | None = None
    direct_permissions: frozenset[str] | None = None
    kind: str = ''

    @property
    def resolved_kind(self) -> str:
        if self.kind:
            return self.kind
        if (self.id or '').startswith('shared:'):
            return 'shared'
        return 'slack' if (self.id or '').startswith('slack:') else 'individual'

    @classmethod
    def from_principal(cls, principal) -> 'GovernanceActor':
        """From a native ProductPrincipal (id, kind, method, email, role, permissions)."""
        kind = getattr(principal, 'kind', '')
        individual = kind in {'google', 'cloudflare'} and getattr(principal, 'method', '') in {'google', 'cloudflare'}
        permissions = getattr(principal, 'permissions', None)
        return cls(id=principal.id, email=(principal.email or '').strip().lower() if individual else '',
                   builtin_role=principal.role,
                   permissions=None if permissions is None else frozenset(permissions),
                   kind='individual' if individual else 'shared' if kind == 'shared' else kind or 'unknown')

    @classmethod
    def from_session(cls, info: Mapping[str, Any]) -> 'GovernanceActor':
        """From a legacy Security.session_info dict, which carries no permission snapshot."""
        method, role = info.get('method', 'password'), info.get('role', '')
        if method in {'google', 'cloudflare'}:
            identity = info.get('identity') or {}
            email = str(identity.get('email', '')).strip().lower()
            subject = identity.get('sub') if method == 'google' else ''
            return cls(id=f'google:{subject}' if subject else f'{method}:{email}', email=email,
                       builtin_role=None, kind='individual')
        if method in {'local', 'password'}:
            return cls(id=f'shared:{method}:{role}', builtin_role=None, kind='shared')
        return cls(id='', builtin_role=None, kind='unknown')


def shared_label(actor_id) -> str | None:
    """'Local preview admin' or 'Shared password member' for a shared:<method>:<role> id, else None."""
    parts = actor_id.split(':') if isinstance(actor_id, str) else []
    if len(parts) != 3 or parts[0] != 'shared' or parts[1] not in {'local', 'password'} \
            or parts[2] not in BUILTIN_PERMISSIONS:
        return None
    return ('Local preview ' if parts[1] == 'local' else 'Shared password ') + parts[2]


def actor_label(actor) -> str:
    """The updated_by/audit label of a governance actor; the same text as Authority.label.

    Accepts a GovernanceActor, a ProductPrincipal (only an individual's email
    counts, never a Slack-claimed one), a legacy session dict, or any object
    with string .id and .email. The label is the lowercased email when present,
    the shared sign-in name for shared:<method>:<role> ids, otherwise the id.
    TypeError when no bounded label exists, so callers fail before any write.
    """
    if isinstance(actor, Mapping) and 'method' in actor:
        actor = GovernanceActor.from_session(actor)
    elif not isinstance(actor, GovernanceActor) and isinstance(individual := getattr(actor, 'individual', None), bool):
        email = getattr(actor, 'email', '') if individual else ''
        actor = GovernanceActor(id=getattr(actor, 'id', ''), email=email if isinstance(email, str) else '')
    email, identity = getattr(actor, 'email', None), getattr(actor, 'id', None)
    if isinstance(email, str) and email.strip():
        label = email.strip().lower()
    else:
        label = identity.strip() if isinstance(identity, str) else ''
        label = shared_label(label) or label
    if not label or len(label) > 512 or '\x00' in label:
        raise TypeError('Governance changes need an authenticated actor with an id or email.')
    return label


def coerce_actor(actor) -> GovernanceActor | None:
    if actor is None or isinstance(actor, GovernanceActor):
        return actor
    if isinstance(actor, Mapping):
        if 'method' in actor:
            return GovernanceActor.from_session(actor)
        fields = ('id', 'email', 'builtin_role', 'permissions', 'direct_permissions', 'kind')
        values = {key: actor[key] for key in fields if key in actor}
        for key in ('permissions', 'direct_permissions'):
            if values.get(key) is not None:
                values[key] = frozenset(values[key])
        return GovernanceActor(**values)
    return GovernanceActor.from_principal(actor)


@dataclass(frozen=True)
class Authority:
    """An actor re-resolved inside the current transaction. grantable None: built-in admin."""
    label: str
    email: str
    builtin_admin: bool
    permissions: frozenset[str]
    grantable: frozenset[str] | None

    @property
    def delegate(self) -> bool:
        return self.grantable is not None

    def require(self, permission: str) -> 'Authority':
        if permission not in self.permissions:
            raise GovernanceForbidden(FORBIDDEN)
        return self

    def bound(self, permissions: Iterable[str], detail: str = AMPLIFY) -> None:
        # Delegation never amplifies: only directly held permissions count.
        if self.grantable is not None and not frozenset(permissions) <= self.grantable:
            raise GovernanceForbidden(detail)


def _view(row) -> dict[str, Any]:
    return {'id': row['id'], 'name': row['name'], 'description': row['description'],
            'permissions': sorted(role_permissions(row['permissions'])), 'revision': int(row['revision']),
            'archived': bool(row['archived']), 'updated_at': row['updated_at'], 'updated_by': row['updated_by']}


class EnterpriseRoles:
    """Revisioned custom roles, assignments and group grants over a canonical Store.

    Methods are synchronous; native routes call them through asyncio.to_thread.
    actor is a GovernanceActor, a ProductPrincipal, or a legacy session dict.
    """

    def __init__(self, user_roles):
        self.user_roles = user_roles
        self.store = user_roles.store
        if self.store.schema_updates:
            from .schema_initializers import initialize_governance_audit, initialize_scim
            for initialize in (initialize_schema, initialize_scim, initialize_governance_audit):
                initialize(self.store)

    def authority_in(self, conn, actor) -> Authority:
        actor = coerce_actor(actor)
        if actor is None:
            raise GovernanceUnauthenticated('Sign in to the workspace.')
        claimed = ALL_PERMISSIONS if actor.permissions is None else actor.permissions
        claimed_direct = ALL_PERMISSIONS if actor.direct_permissions is None else actor.direct_permissions
        kind = actor.resolved_kind
        if kind == 'shared':
            role = shared_actor_role(actor.id, self.user_roles.settings)
            if role is None or actor.builtin_role not in {None, role}:
                raise GovernanceForbidden(FORBIDDEN)
            permissions = BUILTIN_PERMISSIONS[role] & claimed
            admin = role == 'admin' and permissions == ALL_PERMISSIONS
            return Authority(shared_label(actor.id) or actor.id, '', admin, permissions,
                             None if admin else permissions & claimed_direct)
        if kind != 'individual':
            raise GovernanceForbidden(FORBIDDEN)
        email = (actor.email or '').strip().lower()
        if not self.user_roles.eligible(email):
            raise GovernanceForbidden(FORBIDDEN)
        role = self.user_roles.role_in(conn, email)
        state = resolve_access(canonical_fetch(conn), email, role)
        if state.scim_active is False:
            raise GovernanceForbidden(DEACTIVATED)
        permissions = state.permissions & claimed
        admin = role == 'admin' and actor.builtin_role in {None, 'admin'} and permissions == ALL_PERMISSIONS
        return Authority(email, email, admin, permissions,
                         None if admin else state.direct_permissions & permissions & claimed_direct)

    def authorize_in(self, conn, actor, permission: str) -> Authority:
        return self.authority_in(conn, actor).require(permission)

    @staticmethod
    def live_role_in(conn, role_id: str):
        if role_id in BUILTIN_PERMISSIONS:
            return None
        row = conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone()
        return row if row and not row['archived'] else None

    def _held_role_permissions_in(self, conn, role_id: str | None) -> frozenset[str]:
        row = self.live_role_in(conn, role_id) if role_id else None
        return role_permissions(row['permissions']) if row else frozenset()

    @staticmethod
    def _refuse_own_role_in(conn, authority: Authority, role_id: str) -> None:
        """A delegate may not redefine a role that reaches them, in either direction.

        Widening a role their directory group already holds would give them a
        group-derived copy of their direct authority that outlives the direct
        role and that the identity provider, not an administrator, controls.
        Membership matches set_group_role_in: any live group and user row.
        """
        if not authority.delegate:
            return
        if conn.execute('SELECT 1 FROM enterprise_role_assignments WHERE email=? AND role_id=?',
                        (authority.email, role_id)).fetchone():
            raise GovernanceForbidden(SELF)
        if conn.execute('''SELECT 1 FROM enterprise_group_roles r
                JOIN scim_groups g ON g.id=r.group_id AND g.deleted_at=''
                JOIN scim_group_members m ON m.group_id=g.id
                JOIN scim_users u ON u.id=m.user_id AND u.deleted_at=''
                WHERE r.role_id=? AND u.user_name=? LIMIT 1''', (role_id, authority.email)).fetchone():
            raise GovernanceForbidden(OWN_GROUP)

    def listing(self, actor=None) -> dict[str, Any]:
        """GET /api/admin/roles. Without an actor the caller authorized it and nothing is grantable."""
        with self.store.connect() as conn:
            conn.begin_read()
            authority = self.authorize_in(conn, actor, 'roles.manage') if actor is not None else None
            roles = sorted((_view(row) for row in conn.execute('SELECT * FROM enterprise_roles')),
                           key=lambda role: (role['name'].casefold(), role['id']))
            names = {role['id']: role['name'] for role in roles}
            assignments = [{
                'email': row['email'], 'role_id': row['role_id'], 'role_name': names.get(row['role_id'], row['role_id']),
                'revision': int(row['revision']), 'role_revision': int(row['role_revision']),
                'updated_at': row['updated_at'], 'updated_by': row['updated_by'],
            } for row in conn.execute('''SELECT a.email,a.role_id,a.revision,a.updated_at,a.updated_by,
                    COALESCE(u.revision,0) AS role_revision FROM enterprise_role_assignments a
                    LEFT JOIN user_roles u ON u.email=a.email WHERE a.role_id<>'member' ORDER BY a.email''')]
            group_roles = [{
                'group_id': row['group_id'], 'group_name': row['display_name'], 'role_id': row['role_id'],
                'role_name': names.get(row['role_id']) if row['role_id'] else None,
                'revision': int(row['revision']), 'updated_at': row['updated_at'], 'updated_by': row['updated_by'],
            } for row in conn.execute('''SELECT r.group_id,r.role_id,r.revision,r.updated_at,r.updated_by,g.display_name
                    FROM enterprise_group_roles r JOIN scim_groups g ON g.id=r.group_id AND g.deleted_at=''
                    ORDER BY g.display_key,r.group_id''')]
            # Active members, which are the people a grant applies to; one aggregate, not one read per group.
            groups = [{'id': row['id'], 'display_name': row['display_name'], 'member_count': int(row['member_count'])}
                      for row in conn.execute('''SELECT g.id,g.display_name,g.display_key,COUNT(u.id) AS member_count
                          FROM scim_groups g LEFT JOIN scim_group_members m ON m.group_id=g.id
                          LEFT JOIN scim_users u ON u.id=m.user_id AND u.deleted_at='' AND u.active=1
                          WHERE g.deleted_at='' GROUP BY g.id,g.display_name,g.display_key
                          ORDER BY g.display_key,g.id''')]
        grantable = [] if authority is None else None if authority.grantable is None else sorted(authority.grantable)
        return {'roles': roles, 'assignments': assignments, 'group_roles': group_roles, 'groups': groups,
                'grantable': grantable, 'builtin_admin': bool(authority and authority.builtin_admin)}

    def _write(self, operation, *args):
        with self.store.connect() as conn:
            conn.begin_write()
            return operation(conn, *args)

    def create(self, body: RoleCreate, actor) -> dict[str, Any]:
        return self._write(self.create_in, body, actor)

    def create_in(self, conn, body: RoleCreate, actor) -> dict[str, Any]:
        authority = self.authorize_in(conn, actor, 'roles.manage')
        authority.bound(body.permissions)
        # Archived ids stay reserved: assignments and audit history name them.
        if conn.execute('SELECT 1 FROM enterprise_roles WHERE id=?', (body.id,)).fetchone():
            raise GovernanceConflict('A role with this ID already exists.')
        stamp = timestamp()
        conn.execute('''INSERT INTO enterprise_roles(id,name,description,permissions,revision,archived,
            updated_by,created_at,updated_at) VALUES(?,?,?,?,1,0,?,?,?)''',
            (body.id, body.name, body.description, json.dumps(body.permissions), authority.label, stamp, stamp))
        record_event_in(conn, 'role.created', authority.label, 'role', body.id,
                        {'permissions': body.permissions, 'revision': 1})
        return _view(conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (body.id,)).fetchone())

    def update(self, role_id: str, body: RoleUpdate, actor) -> dict[str, Any]:
        return self._write(self.update_in, role_id, body, actor)

    def update_in(self, conn, role_id: str, body: RoleUpdate, actor) -> dict[str, Any]:
        if role_id in BUILTIN_PERMISSIONS:
            raise GovernanceInvalid('Built-in roles cannot be edited.')
        authority = self.authorize_in(conn, actor, 'roles.manage')
        old = conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone()
        if old is None:
            raise GovernanceNotFound('Role not found.')
        if old['archived']:
            raise GovernanceConflict('Archived roles cannot be edited.')
        if body.revision != old['revision']:
            raise GovernanceConflict(STALE)
        self._refuse_own_role_in(conn, authority, role_id)
        previous = role_permissions(old['permissions'])
        # Narrowing removes access just as widening adds it.
        authority.bound(previous, HELD_ROLE)
        authority.bound(body.permissions)
        revision = int(old['revision']) + 1
        conn.execute('''UPDATE enterprise_roles SET name=?,description=?,permissions=?,revision=?,
            updated_by=?,updated_at=? WHERE id=?''',
            (body.name, body.description, json.dumps(body.permissions), revision, authority.label, timestamp(), role_id))
        record_event_in(conn, 'role.updated', authority.label, 'role', role_id,
                        {'previous': sorted(previous), 'permissions': body.permissions, 'revision': revision})
        return _view(conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone())

    def save(self, body: RoleCreate | RoleUpdate, actor, role_id: str | None = None) -> dict[str, Any]:
        """Create (role_id None, RoleCreate) or update an existing role (RoleUpdate)."""
        if role_id is None:
            if not isinstance(body, RoleCreate):
                raise TypeError('Creating a role requires RoleCreate.')
            return self.create(body, actor)
        if not isinstance(body, RoleUpdate):
            raise TypeError('Updating a role requires RoleUpdate.')
        return self.update(role_id, body, actor)

    def archive(self, role_id: str, revision: int, actor) -> dict[str, Any]:
        return self._write(self.archive_in, role_id, revision, actor)

    def archive_in(self, conn, role_id: str, revision: int, actor) -> dict[str, Any]:
        if role_id in BUILTIN_PERMISSIONS:
            raise GovernanceInvalid('Built-in roles cannot be archived.')
        authority = self.authorize_in(conn, actor, 'roles.manage')
        old = conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone()
        if old is None:
            raise GovernanceNotFound('Role not found.')
        if old['revision'] != revision:
            raise GovernanceConflict(STALE)
        if old['archived']:
            return _view(old)
        self._refuse_own_role_in(conn, authority, role_id)
        previous = role_permissions(old['permissions'])
        # Directly assigned people lose every permission of an archived role.
        authority.bound(previous, HELD_ROLE)
        conn.execute('UPDATE enterprise_roles SET archived=1,revision=?,updated_by=?,updated_at=? WHERE id=?',
                     (revision + 1, authority.label, timestamp(), role_id))
        record_event_in(conn, 'role.archived', authority.label, 'role', role_id,
                        {'permissions': sorted(previous), 'revision': revision + 1})
        return _view(conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone())

    def assign(self, body: RoleAssignment, actor) -> dict[str, Any]:
        if body.role_id == 'admin':
            raise GovernanceInvalid('Grant administrator access on the Users page.')
        if not self.user_roles.eligible(body.email):
            raise GovernanceInvalid(INELIGIBLE)
        return self._write(self.assign_in, body, actor)

    def assign_in(self, conn, body: RoleAssignment, actor) -> dict[str, Any]:
        authority = self.authorize_in(conn, actor, 'roles.manage')
        email = body.email
        if body.role_id == 'member':
            granted, role_name = MEMBER_PERMISSIONS, 'Member'
        else:
            role = self.live_role_in(conn, body.role_id)
            if role is None:
                raise GovernanceInvalid('Choose an active workspace role.')
            granted, role_name = role_permissions(role['permissions']), role['name']
        if authority.delegate and email == authority.email:
            raise GovernanceForbidden(SELF)
        row = conn.execute('SELECT * FROM enterprise_role_assignments WHERE email=?', (email,)).fetchone()
        current = row['role_id'] if row and row['role_id'] != 'member' else None
        revision = int(row['revision']) if row else 0
        # A 'member' row equals no row, which the roles page shows as revision 0.
        if body.revision != revision and not (current is None and body.revision == 0):
            raise GovernanceConflict(STALE)
        base = conn.execute('SELECT revision FROM user_roles WHERE email=?', (email,)).fetchone()
        role_revision = int(base['revision']) if base else 0
        # The users page changes built-in roles; a stale view of either page conflicts.
        if body.role_revision is not None and body.role_revision != role_revision:
            raise GovernanceConflict(STALE)
        if self.user_roles.role_in(conn, email) == 'admin':
            if authority.delegate:
                raise GovernanceForbidden(ADMIN_ONLY)
            if body.role_id != 'member':
                raise GovernanceConflict('This person is an administrator. Change their built-in role on the Users page first.')
        if authority.delegate:
            authority.bound(MEMBER_PERMISSIONS if current is None
                            else self._held_role_permissions_in(conn, current), HELD_PERSON)
            authority.bound(granted)
        replacement = None if body.role_id == 'member' else body.role_id
        if replacement == current:
            return {'email': email, 'role_id': body.role_id, 'role_name': role_name, 'revision': revision,
                    'role_revision': role_revision, 'updated_at': row['updated_at'] if row else None,
                    'updated_by': row['updated_by'] if row else ''}
        stamp = timestamp()
        conn.execute('''INSERT INTO enterprise_role_assignments(email,role_id,revision,updated_by,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET role_id=excluded.role_id,
            revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
            (email, body.role_id, revision + 1, authority.label, stamp))
        record_event_in(conn, 'role_assignment.updated', authority.label, 'role_assignment', email,
                        {'previous': current or 'member', 'replacement': body.role_id, 'revision': revision + 1})
        return {'email': email, 'role_id': body.role_id, 'role_name': role_name, 'revision': revision + 1,
                'role_revision': role_revision, 'updated_at': stamp, 'updated_by': authority.label}

    def set_group_role(self, group_id: str, body: GroupRoleChange, actor) -> dict[str, Any]:
        if body.role_id == 'admin':
            raise GovernanceInvalid('Administrator access cannot be granted to a group.')
        if body.role_id == 'member':
            raise GovernanceInvalid('Choose a custom role or no additional role.')
        return self._write(self.set_group_role_in, group_id, body, actor)

    def set_group_role_in(self, conn, group_id: str, body: GroupRoleChange, actor) -> dict[str, Any]:
        authority = self.authorize_in(conn, actor, 'roles.manage')
        group = conn.execute("SELECT id,display_name FROM scim_groups WHERE id=? AND deleted_at=''",
                             (group_id,)).fetchone() if GROUP_ID.fullmatch(group_id) else None
        if group is None:
            raise GovernanceNotFound('Directory group not found.')
        granted, role_name = frozenset(), None
        if body.role_id is not None:
            role = self.live_role_in(conn, body.role_id)
            if role is None:
                raise GovernanceInvalid('Choose an active workspace role.')
            granted, role_name = role_permissions(role['permissions']), role['name']
        row = conn.execute('SELECT * FROM enterprise_group_roles WHERE group_id=?', (group_id,)).fetchone()
        revision = int(row['revision']) if row else 0
        if body.revision != revision:
            raise GovernanceConflict(STALE)
        current = row['role_id'] if row else None
        if authority.delegate:
            # A delegate's own group grants would otherwise outlive their direct role.
            if conn.execute('''SELECT 1 FROM scim_group_members m JOIN scim_users u ON u.id=m.user_id
                    WHERE m.group_id=? AND u.user_name=? AND u.deleted_at='' ''', (group_id, authority.email)).fetchone():
                raise GovernanceForbidden(OWN_GROUP)
            authority.bound(self._held_role_permissions_in(conn, current), HELD_GRANT)
            authority.bound(granted)
        view = {'group_id': group_id, 'group_name': group['display_name'], 'role_id': body.role_id,
                'role_name': role_name}
        if current == body.role_id:
            return {**view, 'revision': revision, 'updated_at': row['updated_at'] if row else None,
                    'updated_by': row['updated_by'] if row else ''}
        if current is not None and body.role_id is None:
            narrow_group_in(conn, group_id)
        stamp = timestamp()
        conn.execute('''INSERT INTO enterprise_group_roles(group_id,role_id,revision,updated_by,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET role_id=excluded.role_id,
            revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
            (group_id, body.role_id, revision + 1, authority.label, stamp))
        record_event_in(conn, 'group_role.updated', authority.label, 'group_role', group_id,
                        {'previous': current, 'replacement': body.role_id, 'revision': revision + 1})
        return {**view, 'revision': revision + 1, 'updated_at': stamp, 'updated_by': authority.label}
