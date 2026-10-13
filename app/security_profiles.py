"""Revisioned session policies and fail-closed broker/provider enforcement.

Policies constrain managed connected apps and GitHub operations. Domain egress
is enforced by Substrate's actor policy, never by agent instructions. Session
snapshots and every ancestor remain ceilings; the current organization floor
can further restrict them. Network floor changes require releasing live VMs.
"""
import ipaddress
import json
import re
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .db import now


class ProfilePolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    network_domains: list[str] | None = None
    connected_apps: list[Literal['github', 'linear', 'slack', 'notion']] | None = None
    tools: list[str] | None = None
    git_access: Literal['none', 'read', 'write'] = 'write'

    @field_validator('network_domains')
    @classmethod
    def domains(cls, values):
        if values is None:
            return None
        if len(values) > 200:
            raise ValueError('At most 200 domain names are supported.')
        result = set()
        for value in values:
            host = value.strip().rstrip('.').lower().encode('idna').decode('ascii')
            if len(host) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
                raise ValueError('Use exact DNS hostnames, without URLs, ports or wildcards.')
            if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
                raise ValueError('Invalid DNS hostname.')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError('Use DNS hostnames, not IP addresses.')
            result.add(host)
        return sorted(result)

    @field_validator('tools')
    @classmethod
    def tool_names(cls, values):
        if values is not None and (len(values) > 500 or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,99}', value) for value in values)):
            raise ValueError('Use valid tool names.')
        return sorted(set(values)) if values is not None else None

    @field_validator('connected_apps')
    @classmethod
    def app_names(cls, values):
        return sorted(set(values)) if values is not None else None


class SaveProfile(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=80)
    revision: int = Field(default=0, ge=0, strict=True)
    enabled: bool = True
    policy: ProfilePolicy = Field(default_factory=ProfilePolicy)


class ProfileDefaults(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(default=0, ge=0, strict=True)
    default_profile_id: str = ''
    floor_profile_id: str = ''


def intersect(*policies):
    result = ProfilePolicy().model_dump()
    levels = {'none': 0, 'read': 1, 'write': 2}
    for policy in policies:
        policy = ProfilePolicy.model_validate(policy or {}).model_dump()
        for key in ('network_domains', 'connected_apps', 'tools'):
            value = policy[key]
            if value is not None:
                result[key] = value if result[key] is None else sorted(set(result[key]) & set(value))
        if levels[policy['git_access']] < levels[result['git_access']]:
            result['git_access'] = policy['git_access']
    return result


class SecurityProfiles:
    def __init__(self, store, settings=None, security=None):
        self.store, self.settings, self.security = store, settings, security
        if store.schema_updates:
            initialize_schema(store)
            from .governance_audit import initialize_schema as initialize_audit
            initialize_audit(store)
        store.security_profiles = self

    def _rows(self, sql, values=(), conn=None):
        return [dict(row) for row in conn.execute(sql, values)] if conn else self.store.rows(sql, values)

    def defaults(self, conn=None):
        rows = self._rows('SELECT revision,default_profile_id,floor_profile_id FROM security_profile_defaults WHERE id=1', conn=conn)
        return rows[0] if rows else {'revision': 0, 'default_profile_id': '', 'floor_profile_id': ''}

    def get(self, identity, conn=None, *, enabled=False):
        rows = self._rows('SELECT * FROM security_profiles WHERE id=?', (identity,), conn)
        if not rows:
            raise HTTPException(404, 'Security profile not found.')
        row = rows[0]
        if enabled and not row['enabled']:
            raise HTTPException(409, 'This security profile is disabled.')
        return {**row, 'enabled': bool(row['enabled']), 'policy': json.loads(row['policy'])}

    def catalog(self, admin=False):
        return [{**row, 'enabled': bool(row['enabled']), 'policy': json.loads(row['policy'])}
                for row in self.store.rows('SELECT * FROM security_profiles ORDER BY name,id') if admin or row['enabled']]

    def _network_change(self, before, after, conn):
        if before.get('network_domains') == after.get('network_domains'):
            return
        live = conn.execute("""SELECT 1 FROM runs WHERE deleted_at='' AND
            (sandbox_id<>'' OR (mode='modal' AND status IN ('running','reconnecting','provisioning','awaiting_approval')))
            LIMIT 1""").fetchone()
        if not live and 'durable_sessions' in conn.table_names():
            # Independent control guests have a durable machine identity even
            # while runs.sandbox_id (the user's computer) is empty.
            live = conn.execute("SELECT 1 FROM durable_sessions WHERE COALESCE(json_text(state,'sandbox_id'),'')<>'' LIMIT 1").fetchone()
        if live:
            raise HTTPException(409, 'Release session sandboxes before changing the mandatory network policy.')

    def save(self, identity, body, actor):
        body = SaveProfile.model_validate(body)
        with self.store.connect() as conn:
            conn.begin_write()
            previous = conn.execute('SELECT * FROM security_profiles WHERE id=?', (identity,)).fetchone()
            if (previous['revision'] if previous else 0) != body.revision:
                raise HTTPException(409, 'This profile changed. Reload before saving.')
            defaults = self.defaults(conn)
            if identity in {defaults['default_profile_id'], defaults['floor_profile_id']} and not body.enabled:
                raise HTTPException(409, 'Remove this profile from organization defaults before disabling it.')
            if identity == defaults['floor_profile_id'] and previous:
                self._network_change(json.loads(previous['policy']), body.policy.model_dump(), conn)
            revision = body.revision + 1
            policy = body.policy.model_dump_json()
            stamp = now()
            conn.execute('''INSERT INTO security_profiles(id,name,revision,enabled,policy,updated_by,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,revision=excluded.revision,
                enabled=excluded.enabled,policy=excluded.policy,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                         (identity, body.name, revision, body.enabled, policy, actor, stamp))
            conn.execute('INSERT INTO security_profile_revisions(profile_id,revision,policy,created_by,created_at) VALUES(?,?,?,?,?)',
                         (identity, revision, policy, actor, stamp))
        return self.get(identity)

    def delete(self, identity, actor='Organization admin'):
        # Retain revisions and references for sessions/checkpoints and auditing.
        row = self.get(identity)
        return self.save(identity, {**{key: row[key] for key in ('name', 'revision', 'policy')}, 'enabled': False}, actor)

    def save_defaults(self, body, actor='Organization admin'):
        body = ProfileDefaults.model_validate(body)
        with self.store.connect() as conn:
            conn.begin_write()
            old = self.defaults(conn)
            if old['revision'] != body.revision:
                raise HTTPException(409, 'Organization security defaults changed. Reload before saving.')
            for identity in (body.default_profile_id, body.floor_profile_id):
                if identity:
                    self.get(identity, conn, enabled=True)
            previous = self.get(old['floor_profile_id'], conn)['policy'] if old['floor_profile_id'] else {}
            selected = self.get(body.floor_profile_id, conn)['policy'] if body.floor_profile_id else {}
            self._network_change(ProfilePolicy.model_validate(previous).model_dump(), ProfilePolicy.model_validate(selected).model_dump(), conn)
            conn.execute('''INSERT INTO security_profile_defaults(id,revision,default_profile_id,floor_profile_id,updated_by,updated_at)
                VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,
                default_profile_id=excluded.default_profile_id,floor_profile_id=excluded.floor_profile_id,
                updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
                         (body.revision + 1, body.default_profile_id, body.floor_profile_id, actor, now()))
            from .governance_audit import record_event_in
            record_event_in(conn, 'security.defaults.updated', actor, 'SecurityDefaults', 'workspace')
        return self.defaults()

    def floor(self, conn=None):
        identity = self.defaults(conn)['floor_profile_id']
        return self.get(identity, conn)['policy'] if identity else {}

    def effective(self, run, conn=None):
        """Use authoritative persisted snapshots, including all ancestors."""
        if not run:
            return intersect(self.floor(conn))
        policies, seen, current = [self.floor(conn)], set(), run
        while current:
            identity = current.get('id')
            if identity in seen:
                raise HTTPException(409, 'Security profile lineage is cyclic.')
            if identity:
                seen.add(identity)
                rows = self._rows('SELECT * FROM runs WHERE id=?', (identity,), conn)
                if not rows:
                    raise HTTPException(409, 'Security profile session lineage is missing.')
                current = rows[0]
            try:
                policies.append(json.loads(current.get('security_policy') or '{}'))
            except (TypeError, ValueError):
                raise HTTPException(409, 'The saved session security policy is invalid.') from None
            parent = current.get('parent_run_id') or current.get('side_chat_of')
            if not parent:
                break
            rows = self._rows('SELECT * FROM runs WHERE id=?', (parent,), conn)
            if not rows:
                raise HTTPException(409, 'Security profile parent session is missing.')
            current = rows[0]
        try:
            return intersect(*policies)
        except ValidationError:
            raise HTTPException(409, 'The saved session security policy is invalid.') from None

    def binding(self, profile_id='', *, provider='modal', parent_run_id='', automation_id='', conn=None):
        defaults = self.defaults(conn)
        if automation_id and not profile_id:
            rows = self._rows('SELECT security_profile_id FROM automations WHERE id=?', (automation_id,), conn)
            if not rows:
                raise HTTPException(404, 'Automation not found.')
            profile_id = rows[0]['security_profile_id']
        identity = profile_id or defaults['default_profile_id']
        selected = self.get(identity, conn, enabled=True) if identity else None
        policies = [selected['policy'] if selected else {}, self.floor(conn)]
        if parent_run_id:
            rows = self._rows('SELECT * FROM runs WHERE id=?', (parent_run_id,), conn)
            if not rows:
                raise HTTPException(409, 'Security profile parent session is missing.')
            policies.append(self.effective(rows[0], conn))
        policy = intersect(*policies)
        self.require_provider(policy, provider)
        return {'security_profile_id': identity, 'security_profile_revision': selected['revision'] if selected else 0,
                'security_policy': json.dumps(policy, sort_keys=True)}

    def bind_session(self, run, profile_id='', automation_id='', conn=None):
        run = self.store.run(run) if isinstance(run, str) else run
        if not run:
            raise HTTPException(404, 'Session not found.')
        if run.get('security_policy') not in (None, '', '{}'):
            self.require_provider(self.effective(run, conn), run.get('sandbox_provider', 'modal'))
            return run
        fields = self.binding(profile_id or run.get('security_profile_id', ''), provider=run.get('sandbox_provider', 'modal'),
                              parent_run_id=run.get('parent_run_id', ''), automation_id=automation_id, conn=conn)
        sql = 'UPDATE runs SET security_profile_id=?,security_profile_revision=?,security_policy=? WHERE id=?'
        values = (fields['security_profile_id'], fields['security_profile_revision'], fields['security_policy'], run['id'])
        if conn:
            conn.execute(sql, values)
        else:
            self.store.execute(sql, values)
        return {**run, **fields}

    @staticmethod
    def require_provider(policy, provider):
        if policy.get('network_domains') is not None and provider != 'substrate':
            raise HTTPException(409, 'Domain network policies require Substrate. This provider cannot enforce the selected security profile.')

    def network_hosts(self, run):
        policy = self.effective(run)
        self.require_provider(policy, run.get('sandbox_provider', 'modal'))
        domains = policy['network_domains']
        if domains is None:
            return None
        # The authenticated broker is essential infrastructure, not an app
        # destination. Keep model/service secrets exclusively on the broker.
        broker = urlsplit(self.settings.public_url).hostname if self.settings else None
        if not broker:
            raise HTTPException(503, 'Configure the broker URL before running a network-restricted session.')
        from .sandboxes.substrate import egress_host_allowed
        ceiling = getattr(self.settings, 'substrate_egress_hosts', '*').split(',')
        if not any(egress_host_allowed(broker.lower(), pattern.strip()) for pattern in ceiling):
            raise HTTPException(409, 'Allow the broker hostname in Substrate egress settings before starting this network-restricted session.')
        return sorted(set(domains) | {broker.lower()})

    def allowed_tool(self, run, name, provider=None, write=False):
        policy = self.effective(run)
        if policy['tools'] is not None and name not in policy['tools']:
            return False
        if provider and policy['connected_apps'] is not None and provider not in policy['connected_apps']:
            return False
        if provider == 'github' or name.startswith('github_'):
            if policy['git_access'] == 'none' or (write and policy['git_access'] != 'write'):
                return False
        return True

    def require_tool(self, run, name, provider=None, write=False):
        if not self.allowed_tool(run, name, provider, write):
            raise HTTPException(403, 'This operation is disabled by the session security profile.')

    def require_url(self, run, url):
        domains = self.effective(run)['network_domains']
        if domains is not None and urlsplit(url).hostname not in domains:
            raise HTTPException(403, 'This destination is disabled by the session security profile.')

    def routes(self, security=None):
        security = security or self.security
        router = APIRouter()

        def actor(request):
            security.require(request, permission='security.manage', mutation=True)
            info = security.session_info(request)
            return info.get('identity', {}).get('email') or info.get('method', 'admin')

        @router.get('/api/security-profiles')
        def catalog(request: Request):
            security.require(request)
            return self.catalog()

        @router.get('/api/admin/security-profiles')
        def administration(request: Request):
            security.require(request, permission='security.manage')
            return {'profiles': self.catalog(admin=True), 'defaults': self.defaults(),
                    'network_enforcement': {'supported_providers': ['substrate']}}

        @router.put('/api/admin/security-profiles/defaults')
        def defaults(body: ProfileDefaults, request: Request):
            return self.save_defaults(body, actor(request))

        @router.post('/api/admin/security-profiles', status_code=201)
        def create(body: SaveProfile, request: Request):
            return self.save(uuid4().hex, body, actor(request))

        @router.put('/api/admin/security-profiles/{identity}')
        def save(identity: str, body: SaveProfile, request: Request):
            who = actor(request)
            self.get(identity)
            return self.save(identity, body, who)

        @router.delete('/api/admin/security-profiles/{identity}')
        def delete(identity: str, request: Request):
            who = actor(request)
            return self.delete(identity, who)

        return router


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS security_profiles (
        id TEXT PRIMARY KEY,name TEXT NOT NULL,revision INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,
        policy TEXT NOT NULL,updated_by TEXT NOT NULL,updated_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS security_profile_revisions (
        profile_id TEXT NOT NULL REFERENCES security_profiles(id),revision INTEGER NOT NULL,
        policy TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(profile_id,revision))''')
    store.execute('''CREATE TABLE IF NOT EXISTS security_profile_defaults (
        id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,default_profile_id TEXT NOT NULL DEFAULT '',
        floor_profile_id TEXT NOT NULL DEFAULT '',updated_by TEXT NOT NULL,updated_at TEXT NOT NULL)''')
    with store.connect() as conn:
        columns = conn.column_names('runs')
        for name, definition in (('security_profile_id', "TEXT NOT NULL DEFAULT ''"),
                                 ('security_profile_revision', 'INTEGER NOT NULL DEFAULT 0'),
                                 ('security_policy', "TEXT NOT NULL DEFAULT '{}'")):
            if name not in columns:
                conn.execute(f'ALTER TABLE runs ADD COLUMN {name} {definition}')
        if conn.column_names('automations') and 'security_profile_id' not in conn.column_names('automations'):
            conn.execute("ALTER TABLE automations ADD COLUMN security_profile_id TEXT NOT NULL DEFAULT ''")
