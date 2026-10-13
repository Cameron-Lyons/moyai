"""Revisioned custom roles and directory group grants without changing sign-in."""
import json
import re

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .db import now
from .permissions import BUILTIN_PERMISSIONS, PERMISSIONS, catalog


def normalized_email(value):
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", value):
        raise ValueError('Enter a work email address.')
    return value


class RoleDefinition(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    id: str = Field(pattern=r'^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$', max_length=64)
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default='', max_length=500)
    permissions: list[str]
    revision: int = Field(default=0, ge=0)

    @field_validator('id')
    @classmethod
    def custom_id(cls, value):
        if value in BUILTIN_PERMISSIONS:
            raise ValueError('Built-in roles cannot be edited.')
        return value

    @field_validator('permissions')
    @classmethod
    def known_permissions(cls, values):
        if any(value not in PERMISSIONS for value in values):
            raise ValueError('Choose permissions from the workspace permission catalog.')
        return sorted(set(values))


class RoleAssignment(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    email: str = Field(max_length=254)
    role_id: str = Field(min_length=1, max_length=64)
    revision: int = Field(default=0, ge=0)

    _email = field_validator('email')(normalized_email)


class GroupRole(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    role_id: str | None = Field(default=None, min_length=1, max_length=64)
    revision: int = Field(default=0, ge=0)


class EnterpriseRoles:
    def __init__(self, user_roles):
        self.user_roles = user_roles
        self.store = user_roles.store
        if self.store.schema_updates:
            initialize_schema(self.store)

    @staticmethod
    def metadata(row):
        return {**{key: row[key] for key in ('id', 'name', 'description', 'revision')},
                'permissions': json.loads(row['permissions']), 'archived': bool(row['archived']), 'builtin': False}

    def audit_in(self, conn, action, actor, subject, previous, replacement):
        conn.execute('''INSERT INTO enterprise_role_audit(action,actor,subject,previous,replacement,created_at)
            VALUES(?,?,?,?,?,?)''', (action, actor, subject, json.dumps(previous), json.dumps(replacement), now()))

    def authorize_in(self, conn, actor, permission='roles.manage'):
        if not actor:
            raise HTTPException(401, 'Sign in to the workspace.')
        method = actor.get('method')
        if method in {'google', 'cloudflare'}:
            email = actor.get('identity', {}).get('email', '').strip().lower()
            if permission not in self.user_roles.permissions_in(conn, email):
                raise HTTPException(403, 'Your workspace role does not permit this action.')
            return email
        if method not in {'local', 'password'} or actor.get('role') != 'admin':
            raise HTTPException(403, 'Your workspace role does not permit this action.')
        return 'Local preview admin' if method == 'local' else 'Shared password admin'

    def role_exists_in(self, conn, role_id):
        return role_id in BUILTIN_PERMISSIONS or bool(conn.execute(
            'SELECT 1 FROM enterprise_roles WHERE id=? AND archived=0', (role_id,)).fetchone())

    def role_permissions_in(self, conn, role_id):
        if role_id in BUILTIN_PERMISSIONS:
            return BUILTIN_PERMISSIONS[role_id]
        row = conn.execute('SELECT permissions FROM enterprise_roles WHERE id=? AND archived=0', (role_id,)).fetchone()
        return frozenset(json.loads(row['permissions'])) & PERMISSIONS.keys() if row else frozenset()

    def direct_permissions_in(self, conn, email):
        row = conn.execute('SELECT role_id FROM enterprise_role_assignments WHERE email=?', (email,)).fetchone()
        # None means use the existing member default. An archived/missing assigned
        # custom role deliberately resolves to no permissions, never member access.
        return self.role_permissions_in(conn, row['role_id']) if row else None

    def group_permissions_in(self, conn, email):
        tables = set(conn.table_names())
        if not {'scim_users', 'scim_groups', 'scim_group_members'} <= tables:
            return frozenset()
        rows = conn.execute('''SELECT DISTINCT r.role_id FROM enterprise_group_roles r
            JOIN scim_groups g ON g.id=r.group_id
            JOIN scim_group_members m ON m.group_id=g.id
            JOIN scim_users u ON u.id=m.user_id
            WHERE u.user_name=? AND u.active=1 AND u.deleted_at='' AND g.deleted_at=''
              AND r.role_id IS NOT NULL''', (email,)).fetchall()
        return frozenset().union(*(self.role_permissions_in(conn, row['role_id']) for row in rows))

    def guard_admins_in(self, conn):
        if self.user_roles.settings.google_admins() and not self.user_roles.admins_in(conn):
            raise HTTPException(409, 'Keep at least one active administrator. Promote another user first.')

    def listing(self):
        with self.store.connect() as conn:
            conn.begin_read()
            builtins = [{'id': key, 'name': 'Administrator' if key == 'admin' else 'Internal user',
                         'description': 'Built-in workspace role', 'permissions': sorted(values),
                         'revision': 0, 'builtin': True, 'archived': False}
                        for key, values in BUILTIN_PERMISSIONS.items()]
            roles = [self.metadata(row) for row in conn.execute('SELECT * FROM enterprise_roles ORDER BY name,id')]
            assignments = [dict(row) for row in conn.execute('SELECT email,role_id,revision FROM enterprise_role_assignments ORDER BY email')]
            group_roles = [dict(row) for row in conn.execute('SELECT group_id,role_id,revision FROM enterprise_group_roles ORDER BY group_id')]
            activity = [dict(row) for row in conn.execute('''SELECT id,action,actor,subject,created_at
                FROM enterprise_role_audit ORDER BY id DESC LIMIT 100''')]
        return {'roles': builtins + roles, 'permissions': catalog(), 'assignments': assignments,
                'group_roles': group_roles, 'activity': activity}

    def save(self, body, actor, role_id=None):
        if role_id is not None and role_id != body.id:
            raise HTTPException(422, 'The role ID cannot change.')
        with self.store.connect() as conn:
            conn.begin_write()
            actor_label = self.authorize_in(conn, actor)
            old = conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (body.id,)).fetchone()
            if (old is None and role_id is not None) or (old is not None and role_id is None):
                raise HTTPException(404 if old is None else 409, 'Role not found.' if old is None else 'Choose a new role ID or edit the existing role.')
            if body.revision != (old['revision'] if old else 0):
                raise HTTPException(409, 'This role changed. Refresh before saving.')
            if old and old['archived']:
                raise HTTPException(409, 'This role has been archived. Create a new role instead.')
            revision = body.revision + 1
            stamp = now()
            conn.execute('''INSERT INTO enterprise_roles(id,name,description,permissions,revision,archived,updated_by,created_at,updated_at)
                VALUES(?,?,?,?,?,0,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                description=excluded.description,permissions=excluded.permissions,revision=excluded.revision,
                updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                (body.id, body.name, body.description, json.dumps(body.permissions), revision, actor_label, stamp, stamp))
            result = self.metadata(conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (body.id,)).fetchone())
            self.audit_in(conn, 'role.updated' if old else 'role.created', actor_label, body.id,
                          self.metadata(old) if old else None, result)
        return result

    def archive(self, role_id, revision, actor):
        if role_id in BUILTIN_PERMISSIONS:
            raise HTTPException(422, 'Built-in roles cannot be archived.')
        with self.store.connect() as conn:
            conn.begin_write()
            actor_label = self.authorize_in(conn, actor)
            old = conn.execute('SELECT * FROM enterprise_roles WHERE id=?', (role_id,)).fetchone()
            if not old:
                raise HTTPException(404, 'Role not found.')
            if old['revision'] != revision:
                raise HTTPException(409, 'This role changed. Refresh before archiving.')
            conn.execute('UPDATE enterprise_roles SET archived=1,revision=revision+1,updated_by=?,updated_at=? WHERE id=?',
                         (actor_label, now(), role_id))
            self.audit_in(conn, 'role.archived', actor_label, role_id, self.metadata(old), {'archived': True})
        return {'id': role_id, 'archived': True, 'revision': revision + 1}

    def assign(self, body, actor):
        from .user_roles import RoleChange
        if not self.user_roles.eligible(body.email):
            raise HTTPException(422, 'Use an email in the workspace’s allowed domains.')
        with self.store.connect() as conn:
            conn.begin_write()
            actor_label = self.authorize_in(conn, actor)
            if not self.role_exists_in(conn, body.role_id):
                raise HTTPException(422, 'Choose an active workspace role.')
            old = conn.execute('SELECT * FROM enterprise_role_assignments WHERE email=?', (body.email,)).fetchone()
            if body.revision != (old['revision'] if old else 0):
                raise HTTPException(409, 'This assignment changed. Refresh before saving.')
            base = conn.execute('SELECT revision FROM user_roles WHERE email=?', (body.email,)).fetchone()
            base_role = body.role_id if body.role_id in BUILTIN_PERMISSIONS else 'member'
            # Reuse the existing serialized last-admin check; authorization above
            # permits role administrators while the legacy method checks users.manage.
            self.user_roles.change_in(conn, RoleChange(email=body.email, role=base_role,
                revision=base['revision'] if base else 0), actor, clear_custom=False, authorized_actor=actor_label)
            result = {'email': body.email, 'role_id': body.role_id, 'revision': body.revision + 1}
            conn.execute('''INSERT INTO enterprise_role_assignments(email,role_id,revision,updated_by,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET role_id=excluded.role_id,
                revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                (body.email, body.role_id, result['revision'], actor_label, now()))
            self.audit_in(conn, 'assignment.updated', actor_label, body.email,
                          {key: old[key] for key in result} if old else None, result)
        return result

    def set_group_role_in(self, conn, group_id, role_id, actor, expected_revision=None):
        if role_id == 'admin':
            raise HTTPException(422, 'Assign administrator access directly to a user, not a directory group.')
        if role_id is not None and not self.role_exists_in(conn, role_id):
            raise HTTPException(422, 'Choose an active workspace role.')
        if 'scim_groups' not in conn.table_names() or not conn.execute("SELECT id FROM scim_groups WHERE id=? AND deleted_at=''", (group_id,)).fetchone():
            raise HTTPException(404, 'Directory group not found.')
        old = conn.execute('SELECT * FROM enterprise_group_roles WHERE group_id=?', (group_id,)).fetchone()
        revision = old['revision'] if old else 0
        if expected_revision is not None and expected_revision != revision:
            raise HTTPException(409, 'This group grant changed. Refresh before saving.')
        result = {'group_id': group_id, 'role_id': role_id, 'revision': revision + 1}
        conn.execute('''INSERT INTO enterprise_group_roles(group_id,role_id,revision,updated_by,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET role_id=excluded.role_id,
            revision=excluded.revision,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
            (group_id, role_id, result['revision'], actor, now()))
        self.audit_in(conn, 'group-grant.updated', actor, group_id,
                      {key: old[key] for key in result} if old else None, result)
        return result

    def routes(self, security):
        router = APIRouter()

        @router.get('/api/permissions')
        async def current_permissions(request: Request):
            security.require(request)
            return {'permissions': sorted(security.permissions(request)), 'catalog': catalog(), 'role': security.role(request)}

        @router.get('/api/admin/roles')
        async def roles(request: Request):
            security.require(request, permission='roles.manage')
            return self.listing()

        @router.post('/api/admin/roles', status_code=201)
        async def create_role(body: RoleDefinition, request: Request):
            security.require(request, mutation=True, permission='roles.manage')
            return self.save(body, security.session_info(request))

        @router.put('/api/admin/roles/{role_id}')
        async def edit_role(role_id: str, body: RoleDefinition, request: Request):
            security.require(request, mutation=True, permission='roles.manage')
            return self.save(body, security.session_info(request), role_id)

        @router.delete('/api/admin/roles/{role_id}')
        async def archive_role(role_id: str, request: Request, revision: int = Query(ge=0)):
            security.require(request, mutation=True, permission='roles.manage')
            return self.archive(role_id, revision, security.session_info(request))

        @router.put('/api/admin/role-assignments')
        async def assignment(body: RoleAssignment, request: Request):
            security.require(request, mutation=True, permission='roles.manage')
            return self.assign(body, security.session_info(request))

        @router.put('/api/admin/group-roles/{group_id}')
        async def group_role(group_id: str, body: GroupRole, request: Request):
            security.require(request, mutation=True, permission='roles.manage')
            with self.store.connect() as conn:
                conn.begin_write()
                actor = self.authorize_in(conn, security.session_info(request))
                return self.set_group_role_in(conn, group_id, body.role_id, actor, body.revision)

        return router


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS enterprise_roles (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
        permissions TEXT NOT NULL, revision INTEGER NOT NULL,
        archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
        updated_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS enterprise_role_assignments (
        email TEXT PRIMARY KEY, role_id TEXT NOT NULL, revision INTEGER NOT NULL,
        updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS enterprise_group_roles (
        group_id TEXT PRIMARY KEY, role_id TEXT, revision INTEGER NOT NULL,
        updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS enterprise_role_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, actor TEXT NOT NULL,
        subject TEXT NOT NULL, previous TEXT NOT NULL, replacement TEXT NOT NULL, created_at TEXT NOT NULL)''')
