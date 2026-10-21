"""Administrator-managed Google Workspace roles, separate from spend identities.

Built-in roles stay here; custom roles, assignments and group grants live in
enterprise_roles, which resolves effective permissions for both. Only active
administrators (not SCIM-deactivated or deleted) count toward last-admin
protection, and replacing a custom role from this editor needs explicit
confirmation of the assignment revision the editor saw.

The methods are synchronous and open their own transactions; native routes call
them through asyncio.to_thread, so no database work runs on the event loop.
"""
import re
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .db import now
from .enterprise_roles import (
    ADMIN_ONLY,
    AMPLIFY,
    FORBIDDEN,
    HELD_PERSON,
    SELF,
    STALE,
    EnterpriseRoles,
    GovernanceConflict,
    GovernanceForbidden,
    canonical_fetch,
    resolve_access,
    role_permissions,
    scim_state_in,
)
from .governance_audit import record_event_in
from .permissions import BUILTIN_PERMISSIONS

CUSTOM_ROLE = 'This person has a custom role. Confirm replacing it to continue.'
LAST_ADMIN = 'Keep at least one administrator. Promote another user first.'


class RoleChange(BaseModel):
    """replace_custom_role/access_revision confirm replacing a custom role the editor showed."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    role: Literal['admin', 'member']
    revision: int = Field(ge=0)
    replace_custom_role: bool = False
    access_revision: int | None = Field(default=None, ge=0)

    @field_validator('email')
    @classmethod
    def normalize_email(cls, value):
        value = value.lower()
        if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", value):
            raise ValueError('Enter a work email address.')
        return value


class _Snapshot:
    """Directory rows preloaded once and served to resolve_access without per-person reads."""

    def __init__(self, conn):
        self.scim = {}
        # Later rows win: tombstones first, then live rows, each by update time.
        for row in conn.execute('''SELECT id,user_name,active,deleted_at,access_epoch FROM scim_users
                ORDER BY (deleted_at=''),updated_at,id'''):
            self.scim[row['user_name']] = {'id': row['id'], 'active': row['active'], 'deleted_at': row['deleted_at'],
                                           'access_epoch': row['access_epoch']}
        self.assignments = {row['email']: dict(row) for row in conn.execute(
            'SELECT email,role_id,revision FROM enterprise_role_assignments')}
        self.roles = {row['id']: dict(row) for row in conn.execute(
            'SELECT id,name,permissions,permissions_revision,archived FROM enterprise_roles')}
        self.grants = {}
        for row in conn.execute('''SELECT u.user_name,r.group_id,r.revision,r.role_id,e.permissions,e.archived,
                    e.permissions_revision AS role_revision
                FROM enterprise_group_roles r
                JOIN scim_groups g ON g.id=r.group_id AND g.deleted_at=''
                JOIN scim_group_members m ON m.group_id=g.id
                JOIN scim_users u ON u.id=m.user_id AND u.deleted_at='' AND u.active=1
                LEFT JOIN enterprise_roles e ON e.id=r.role_id
                WHERE r.role_id IS NOT NULL ORDER BY r.group_id'''):
            self.grants.setdefault(row['user_name'], []).append(dict(row))

    def fetch(self, name, params):
        if name == 'scim_user':
            row = self.scim.get(params['email'])
            return [row] if row else []
        if name == 'assignment':
            row = self.assignments.get(params['email'])
            return [row] if row else []
        if name == 'role':
            row = self.roles.get(params['role_id'])
            return [row] if row else []
        if name == 'group_grants':
            return self.grants.get(params['email'], [])
        raise KeyError(name)


class UserRoles:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        if store.schema_updates:
            initialize_schema(store)
        self.enterprise = EnterpriseRoles(self)

    def eligible(self, email):
        return bool(email and email.rpartition('@')[2] in self.settings.google_domains())

    def role_in(self, conn, email):
        row = conn.execute('SELECT role FROM user_roles WHERE email=?', (email,)).fetchone()
        return row['role'] if row else ('admin' if email in self.settings.google_admins() else 'member')

    def role_and_revision_in(self, conn, email):
        row = conn.execute('SELECT role,revision FROM user_roles WHERE email=?', (email,)).fetchone()
        return (row['role'], row['revision']) if row else (self.default_role(email), 0)

    def permissions_for_actor_in(self, conn, actor_id):
        from .permissions import shared_actor_role
        if actor_id.startswith('shared:'):
            return BUILTIN_PERMISSIONS.get(shared_actor_role(actor_id, self.settings), frozenset())
        row = conn.execute('SELECT * FROM users WHERE id=?', (actor_id,)).fetchone()
        if row is None:
            return frozenset()
        if row['kind'] in {'google', 'cloudflare'}:
            return self.permissions_in(conn, row['email'])
        if row['kind'] == 'slack':
            from datetime import datetime, timezone
            from .identities import PROFILE_MAX_AGE_SECONDS
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['profile_checked_at'])).total_seconds()
            except (TypeError, ValueError):
                return frozenset()
            if row['profile_eligible'] and not row['profile_conflict'] and 0 <= age < PROFILE_MAX_AGE_SECONDS:
                return self.permissions_in(conn, row['email']) & BUILTIN_PERMISSIONS['member']
        return frozenset()

    def require_actor(self, actor_id, permission, *, connection=None):
        if connection is None:
            with self.store.connect() as conn:
                return self.require_actor(actor_id, permission, connection=conn)
        if permission not in self.permissions_for_actor_in(connection, actor_id):
            raise HTTPException(403, FORBIDDEN)

    def default_role(self, email):
        """The built-in role of an email without a user_roles row."""
        return 'admin' if email in self.settings.google_admins() else 'member'

    def role(self, email):
        with self.store.connect() as conn:
            return self.role_in(conn, email.strip().lower())

    def active_email_in(self, conn, email):
        """Unmanaged emails stay active; SCIM-deactivated or deleted emails do not."""
        return scim_state_in(conn, email) is not False

    def access_in(self, conn, email, role=None):
        """Governance state; role is the already-read built-in role of this email."""
        email = email.strip().lower()
        return resolve_access(canonical_fetch(conn), email, role or self.role_in(conn, email))

    def permissions_in(self, conn, email):
        email = email.strip().lower()
        return self.access_in(conn, email).permissions if self.eligible(email) else frozenset()

    def permissions(self, email):
        with self.store.connect() as conn:
            return self.permissions_in(conn, email)

    def admin_holders_in(self, conn):
        """Built-in administrator role holders, before eligibility and directory status."""
        admins = set(self.settings.google_admins())
        for row in conn.execute('SELECT email,role FROM user_roles'):
            if row['role'] == 'admin':
                admins.add(row['email'])
            else:
                admins.discard(row['email'])
        return admins

    def admins_in(self, conn):
        """Eligible administrators whose directory account is not deactivated or deleted."""
        holders = sorted(email for email in self.admin_holders_in(conn) if self.eligible(email))
        inactive = set()
        for offset in range(0, len(holders), 500):
            chunk = holders[offset:offset + 500]
            states = {}
            for row in conn.execute(f'''SELECT user_name,active,deleted_at FROM scim_users
                    WHERE user_name IN ({','.join('?' * len(chunk))}) ORDER BY (deleted_at=''),updated_at,id''', chunk):
                states[row['user_name']] = bool(row['active'] and not row['deleted_at'])
            inactive |= {email for email, active in states.items() if not active}
        return set(holders) - inactive

    def directory(self):
        with self.store.connect() as conn:
            conn.begin_read()
            assignments = {row['email']: dict(row) for row in conn.execute('SELECT * FROM user_roles')}
            people = {email: {'email': email, 'name': '', 'has_signed_in': False, 'last_seen': None}
                      for email in set(self.settings.google_admins()) | assignments.keys() if self.eligible(email)}
            # Slack profiles may appear before Google sign-in. They do not grant authentication.
            for row in conn.execute("SELECT email,name,kind,updated_at FROM users WHERE kind IN ('google','cloudflare') OR (kind='slack' AND profile_eligible=1) ORDER BY updated_at"):
                email = row['email'].strip().lower()
                if not self.eligible(email):
                    continue
                person = people.setdefault(email, {'email': email, 'name': '', 'has_signed_in': False, 'last_seen': None})
                if row['kind'] in {'google', 'cloudflare'}:
                    person.update(name=row['name'], has_signed_in=True, last_seen=row['updated_at'])
                elif not person['name']:
                    person['name'] = row['name']
            # A fixed number of statements for any directory size, with the same rules as access_in.
            snapshot = _Snapshot(conn)
            for email, person in people.items():
                assignment = assignments.get(email)
                role = assignment['role'] if assignment else self.default_role(email)
                state = resolve_access(snapshot.fetch, email, role)
                access_revision = int(snapshot.assignments.get(email, {}).get('revision', 0))
                person.update(
                    role=role, revision=assignment['revision'] if assignment else 0,
                    access_role_id=state.role_id, access_role_name=state.role_name or state.role_id,
                    access_revision=access_revision,
                    access_role={'id': state.role_id, 'name': state.role_name or state.role_id,
                                 'revision': access_revision} if state.role_id else None,
                    active=state.scim_active is not False, permissions=sorted(state.permissions),
                )
            audit = [dict(row) for row in conn.execute('SELECT email,previous_role,role,actor,created_at FROM user_role_audit ORDER BY id DESC LIMIT 30')]
        return {'users': sorted(people.values(), key=lambda row: (row['role'] != 'admin', row['email'])),
                'activity': audit, 'domains': sorted(self.settings.google_domains())}

    def change(self, body, actor):
        """actor: a GovernanceActor, ProductPrincipal or legacy session dict; rechecked in the writer."""
        if not actor:
            raise HTTPException(401, 'Sign in to the workspace.')
        if not self.eligible(body.email):
            raise HTTPException(422, 'Use an email in the workspace’s allowed Google domains.')
        with self.store.connect() as conn:
            # Serialize authorization, the last-admin check, and the write. Two
            # concurrent demotions must never remove both remaining admins.
            conn.begin_write()
            return self.change_in(conn, body, actor)

    def change_in(self, conn, body, actor):
        authority = self.enterprise.authorize_in(conn, actor, 'users.manage')
        previous = conn.execute('SELECT * FROM user_roles WHERE email=?', (body.email,)).fetchone()
        revision = previous['revision'] if previous else 0
        if body.revision != revision:
            raise GovernanceConflict(STALE)
        old_role = self.role_in(conn, body.email)
        if authority.delegate and 'admin' in {old_role, body.role}:
            raise GovernanceForbidden(ADMIN_ONLY)
        if authority.delegate and body.email == authority.email:
            raise GovernanceForbidden(SELF)
        assignment = conn.execute('SELECT * FROM enterprise_role_assignments WHERE email=?', (body.email,)).fetchone()
        custom = assignment['role_id'] if assignment and assignment['role_id'] != 'member' else None
        if body.replace_custom_role:
            # The confirmation names the assignment the editor showed.
            if assignment is None or body.access_revision != assignment['revision']:
                raise GovernanceConflict(STALE)
        elif custom:
            raise GovernanceConflict(CUSTOM_ROLE)
        if custom:
            if 'roles.manage' not in authority.permissions:
                raise GovernanceForbidden(FORBIDDEN)
            row = self.enterprise.live_role_in(conn, custom)
            authority.bound(role_permissions(row['permissions']) if row else frozenset(), HELD_PERSON)
        authority.bound(BUILTIN_PERMISSIONS[body.role], AMPLIFY)
        # Only the last active administrator is protected; a deactivated one can
        # still be demoted so reprovisioning cannot restore a latent admin role.
        if old_role == 'admin' and body.role != 'admin' and self.admins_in(conn) == {body.email}:
            raise GovernanceConflict(LAST_ADMIN)
        if body.role == 'admin' and old_role != 'admin' and not self.active_email_in(conn, body.email):
            raise GovernanceConflict('Activate this directory account before assigning administrator access.')
        if custom:
            conn.execute('''UPDATE enterprise_role_assignments SET role_id='member',revision=revision+1,
                updated_by=?,updated_at=? WHERE email=?''', (authority.label, now(), body.email))
            record_event_in(conn, 'role_assignment.updated', authority.label, 'role_assignment', body.email,
                            {'previous': custom, 'replacement': body.role, 'revision': assignment['revision'] + 1})
        # Replacing only a custom role leaves an unchanged built-in role unwritten.
        if (previous and previous['role'] == body.role) or (custom and old_role == body.role):
            return {'email': body.email, 'role': body.role, 'revision': revision}
        known = previous or body.email in self.settings.google_admins() or conn.execute(
            'SELECT 1 FROM users WHERE lower(email)=? LIMIT 1', (body.email,)).fetchone()
        stamp = now()
        conn.execute('''INSERT INTO user_roles VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET
            role=excluded.role,revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                     (body.email, body.role, revision + 1, authority.label, stamp))
        conn.execute('INSERT INTO user_role_audit(email,previous_role,role,actor,created_at) VALUES(?,?,?,?,?)',
                     (body.email, old_role if known else '', body.role, authority.label, stamp))
        return {'email': body.email, 'role': body.role, 'revision': revision + 1}


from .schema_initializers import initialize_user_roles as initialize_schema
