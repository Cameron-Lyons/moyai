"""Administrator-managed Google Workspace roles, separate from spend identities."""
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .db import now
from .permissions import BUILTIN_PERMISSIONS, MEMBER_PERMISSIONS, shared_actor_role


class RoleChange(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    role: Literal['admin', 'member']
    revision: int = Field(ge=0)

    @field_validator('email')
    @classmethod
    def normalize_email(cls, value):
        value = value.lower()
        if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", value):
            raise ValueError('Enter a work email address.')
        return value


class UserRoles:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        if store.schema_updates:
            initialize_schema(store)
        from .enterprise_roles import EnterpriseRoles
        self.enterprise = EnterpriseRoles(self)

    def eligible(self, email):
        return bool(email and email.rpartition('@')[2] in self.settings.google_domains())

    def role_in(self, conn, email):
        row = conn.execute('SELECT role FROM user_roles WHERE email=?', (email,)).fetchone()
        return row['role'] if row else ('admin' if email in self.settings.google_admins() else 'member')

    def role(self, email):
        with self.store.connect() as conn:
            return self.role_in(conn, email.strip().lower())

    def active_email_in(self, conn, email):
        from .scim import active_for_email_in
        return active_for_email_in(conn, email)

    def active_actor_in(self, conn, actor_id):
        from .scim import active_for_actor_in
        return active_for_actor_in(conn, actor_id)

    def permissions_in(self, conn, email):
        email = email.strip().lower()
        if not self.eligible(email) or not self.active_email_in(conn, email):
            return frozenset()
        if self.role_in(conn, email) == 'admin':
            return BUILTIN_PERMISSIONS['admin']
        direct = self.enterprise.direct_permissions_in(conn, email)
        return (MEMBER_PERMISSIONS if direct is None else direct) | self.enterprise.group_permissions_in(conn, email)

    def permissions(self, email):
        with self.store.connect() as conn:
            return self.permissions_in(conn, email)

    def permissions_for_actor_in(self, conn, actor_id):
        if not actor_id or not self.active_actor_in(conn, actor_id):
            return frozenset()
        if actor_id.startswith('shared:'):
            return BUILTIN_PERMISSIONS.get(shared_actor_role(actor_id, self.settings), frozenset())
        user = conn.execute('SELECT * FROM users WHERE id=?', (actor_id,)).fetchone()
        if not user:
            return frozenset()
        if user['kind'] in {'google', 'cloudflare'}:
            return self.permissions_in(conn, user['email'])
        if user['kind'] == 'slack':
            # The event sender is authenticated by Slack. Only a current verified
            # company profile can inherit email-based roles; accounting links do
            # not authorize elevated permissions.
            from datetime import datetime, timezone
            from .identities import PROFILE_MAX_AGE_SECONDS
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(user['profile_checked_at'])).total_seconds()
            except (ValueError, TypeError):
                age = PROFILE_MAX_AGE_SECONDS
            if user['profile_eligible'] and not user['profile_conflict'] and 0 <= age < PROFILE_MAX_AGE_SECONDS:
                permissions = self.permissions_in(conn, user['email'])
                verified = conn.execute("SELECT id FROM users WHERE email=? AND kind IN ('google','cloudflare')",
                                        (user['email'],)).fetchall()
                # A Slack profile or accounting link alone cannot turn a
                # preassigned email into an elevated, verified web identity.
                return permissions if len(verified) == 1 else permissions & MEMBER_PERMISSIONS
            # A known assigned/provisioned identity must not regain member access
            # by losing profile verification. Unmapped Slack events keep their
            # existing member-level session access.
            if user['email'] and (conn.execute('SELECT 1 FROM enterprise_role_assignments WHERE email=?',
                    (user['email'],)).fetchone() or not self.active_email_in(conn, user['email'])):
                return frozenset()
            return MEMBER_PERMISSIONS
        return frozenset()

    def is_admin_actor_in(self, conn, actor_id):
        """Resolve the built-in ownership override, never a custom allowlist."""
        if not actor_id or not self.active_actor_in(conn, actor_id):
            return False
        if actor_id.startswith('shared:'):
            return shared_actor_role(actor_id, self.settings) == 'admin'
        user = conn.execute('SELECT kind,email FROM users WHERE id=?', (actor_id,)).fetchone()
        return bool(user and user['kind'] in {'google', 'cloudflare'}
                    and self.eligible(user['email']) and self.active_email_in(conn, user['email'])
                    and self.role_in(conn, user['email']) == 'admin')

    def require_actor(self, actor_id, permission, *, connection=None):
        if permission not in BUILTIN_PERMISSIONS['admin']:
            raise ValueError('Unknown workspace permission.')
        if connection is None:
            with self.store.connect() as conn:
                return self.require_actor(actor_id, permission, connection=conn)
        if not self.active_actor_in(connection, actor_id):
            raise HTTPException(403, 'This workspace account has been deactivated.')
        if permission not in self.permissions_for_actor_in(connection, actor_id):
            raise HTTPException(403, 'Your workspace role does not permit this action.')

    def admins_in(self, conn):
        admins = set(self.settings.google_admins())
        for row in conn.execute('SELECT email,role FROM user_roles'):
            if row['role'] == 'admin':
                admins.add(row['email'])
            else:
                admins.discard(row['email'])
        return {email for email in admins if self.eligible(email) and self.active_email_in(conn, email)}

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
            for email, person in people.items():
                assignment = assignments.get(email, {})
                custom = conn.execute('SELECT role_id,revision FROM enterprise_role_assignments WHERE email=?', (email,)).fetchone()
                person.update(role=self.role_in(conn, email), revision=assignment.get('revision', 0),
                              access_role_id=custom['role_id'] if custom else self.role_in(conn, email),
                              access_revision=custom['revision'] if custom else 0,
                              active=self.active_email_in(conn, email), permissions=sorted(self.permissions_in(conn, email)))
            audit = [dict(row) for row in conn.execute('SELECT email,previous_role,role,actor,created_at FROM user_role_audit ORDER BY id DESC LIMIT 30')]
        return {'users': sorted(people.values(), key=lambda row: (row['role'] != 'admin', row['email'])),
                'activity': audit, 'domains': sorted(self.settings.google_domains())}

    def change(self, body, actor):
        if not actor:
            raise HTTPException(401, 'Sign in to the workspace.')
        if not self.eligible(body.email):
            raise HTTPException(422, 'Use an email in the workspace’s allowed Google domains.')
        with self.store.connect() as conn:
            # Serialize authorization, the last-admin check, and the write. Two
            # concurrent demotions must never remove both remaining admins.
            conn.begin_write()
            return self.change_in(conn, body, actor)

    def change_in(self, conn, body, actor, *, clear_custom=True, authorized_actor=None):
        actor_label = authorized_actor or self.enterprise.authorize_in(conn, actor, 'users.manage')
        previous = conn.execute('SELECT * FROM user_roles WHERE email=?', (body.email,)).fetchone()
        revision = previous['revision'] if previous else 0
        if body.revision != revision:
            raise HTTPException(409, 'This role changed since you opened it. Refresh and try again.')
        old_role = self.role_in(conn, body.email)
        if old_role == 'admin' and body.role != 'admin' and len(self.admins_in(conn)) <= 1:
            raise HTTPException(409, 'Keep at least one administrator. Promote another user first.')
        if body.role == 'admin' and not self.active_email_in(conn, body.email):
            raise HTTPException(409, 'Activate this directory account before assigning administrator access.')
        if clear_custom:
            custom = conn.execute('SELECT * FROM enterprise_role_assignments WHERE email=?', (body.email,)).fetchone()
            if custom and custom['role_id'] != body.role:
                conn.execute('UPDATE enterprise_role_assignments SET role_id=?,revision=revision+1,updated_by=?,updated_at=? WHERE email=?',
                             (body.role, actor_label, now(), body.email))
                self.enterprise.audit_in(conn, 'assignment.updated', actor_label, body.email,
                    {'role_id': custom['role_id']}, {'role_id': body.role})
        if previous and previous['role'] == body.role:
            return {'email': body.email, 'role': body.role, 'revision': revision}
        known = previous or body.email in self.settings.google_admins() or conn.execute(
            'SELECT 1 FROM users WHERE lower(email)=? LIMIT 1', (body.email,)).fetchone()
        stamp = now()
        conn.execute('''INSERT INTO user_roles VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET
            role=excluded.role,revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                     (body.email, body.role, revision + 1, actor_label, stamp))
        conn.execute('INSERT INTO user_role_audit(email,previous_role,role,actor,created_at) VALUES(?,?,?,?,?)',
                     (body.email, old_role if known else '', body.role, actor_label, stamp))
        return {'email': body.email, 'role': body.role, 'revision': revision + 1}

    def routes(self, security):
        router = APIRouter()

        @router.get('/api/admin/users')
        async def users(request: Request):
            security.require(request, admin=True)
            return self.directory()

        @router.put('/api/admin/users/role')
        async def change_role(body: RoleChange, request: Request):
            security.require(request, admin=True, mutation=True)
            return self.change(body, security.session_info(request))

        return router


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS user_roles (
        email TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('admin','member')),
        revision INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS user_role_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL,
        previous_role TEXT NOT NULL, role TEXT NOT NULL,
        actor TEXT NOT NULL, created_at TEXT NOT NULL)''')
