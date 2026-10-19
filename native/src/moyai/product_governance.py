"""Live canonical governance on the native admission and execution transactions."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import Numeric, cast, func, select, text

from .product_governance_models import ProductSessionPolicy


class CanonicalRead:
    """Read-only qmark seam for reviewed canonical governance queries."""
    def __init__(self, session: Any, identity: Any):
        self.session, self.identity = session, identity

    def execute(self, query: str, values=()):
        if not query.lstrip().upper().startswith('SELECT'):
            raise ValueError('Governance snapshots are read-only.')
        query = re.sub(r'\b(FROM|JOIN) ([a-z_]+)\b',
                       lambda match: match[1] + ' ' + self.identity._table(match[2]), query)
        pieces = query.split('?')
        if len(pieces) != len(values) + 1:
            raise ValueError('Governance query bindings changed.')
        sql = pieces[0] + ''.join(f':p{index}' + part for index, part in enumerate(pieces[1:]))
        return self.session.execute(text(sql), {f'p{index}': value for index, value in enumerate(values)}).mappings()


class ProductGovernance:
    def __init__(self, product: Any, database: Any):
        self.product, self.database = product, database
        self.identity = product.identity

    async def principal(self, db, grant, permission='sessions.create'):
        principal = await self.identity.authorize_admission(db, grant)
        principal.require(permission)
        return principal

    async def bind(self, db, session, principal, requested='', inherited_from=None, trusted_profile=False, ceiling=None):
        from app.security_profiles import dump_policy, intersect
        principal.require('sessions.create')
        if requested and not trusted_profile:
            principal.require('security.manage')
        existing = await db.get(ProductSessionPolicy, session.id)
        if existing is not None:
            return existing
        if inherited_from and not requested:
            principal.require('sessions.read')
            parent = await db.get(ProductSessionPolicy, inherited_from)
            from app.security_profiles import SessionBinding
            binding = SessionBinding(parent.profile_id if parent else '', parent.profile_revision if parent else 0,
                                     await self.policy(db, inherited_from))
        else:
            binding = await db.run_sync(lambda sync: self.product.profiles.resolve_for_new_session_in(
                CanonicalRead(sync, self.identity), requested))
        policy = binding.policy
        if inherited_from and requested:
            policy = intersect(policy, await self.policy(db, inherited_from))
        if ceiling is not None:
            policy = intersect(policy, ceiling)
        self.require_provider(policy)
        await db.flush()
        row = ProductSessionPolicy(session_id=session.id, profile_id=binding.profile_id,
                                   profile_revision=binding.revision, policy=dump_policy(policy),
                                   inherited_from=inherited_from)
        db.add(row)
        await db.flush()
        return row

    async def policy(self, db, session_id):
        from app.security_profiles import ProfilePolicy, effective, load_policy
        row = await db.get(ProductSessionPolicy, session_id)
        # Sessions predating the migration had no selected profile. The live
        # mandatory policy still applies to these historical sessions.
        saved = load_policy(row.policy) if row else ProfilePolicy()
        mandatory = await db.run_sync(lambda sync: self.product.profiles.mandatory_in(
            CanonicalRead(sync, self.identity)))
        return effective(saved, mandatory.policy if mandatory else None)

    @staticmethod
    def require_provider(policy):
        # The installed Harness Modal adapter and Lambda provider do not expose
        # a machine-level egress policy. Refuse restricted work before launch.
        if policy.network_domains is not None:
            raise HTTPException(409, 'This native computer provider cannot enforce a network allowlist. Select a policy without network restrictions or use an enforcing provider.')

    async def admission(self, db, session, principal, grants=()):
        principal.require('sessions.create')
        policy = await self.policy(db, session.id)
        self.require_provider(policy)
        if policy.connected_apps is not None and any(grant.kind not in policy.connected_apps for grant in grants):
            raise HTTPException(403, 'A selected connection is disabled by the session security policy.')
        if grants:
            principal.require('connections.read')
        return policy

    async def workspace(self, db, scope, context):
        principal = await self.principal(db, scope.product_grant)
        if context.get('environment_build_id'):
            principal.require('environments.read')
        if context.get('repo_url'):
            principal.require('connections.read')
            policy = await self.policy(db, scope.session_id)
            if policy.git_access == 'none' or (policy.connected_apps is not None and 'github' not in policy.connected_apps):
                raise HTTPException(403, 'The repository exceeds the session security policy.')

    async def check_tool(self, scope, name, *, read_only=None):
        from app.permissions import connector_tool, tool_permission
        async with self.database.sessions.begin() as db:
            principal = await self.principal(db, scope.product_grant, tool_permission(name, read_only=read_only))
            policy = await self.policy(db, scope.session_id)
            self.require_provider(policy)
            connector = connector_tool(name)
            provider, operation = connector if connector else (None, name)
            if policy.tools is not None and not {name, operation, f'{provider}_{operation}'}.intersection(policy.tools):
                raise HTTPException(403, 'This tool is disabled by the session security policy.')
            if provider and policy.connected_apps is not None and provider not in policy.connected_apps:
                raise HTTPException(403, 'This connection is disabled by the session security policy.')
            if provider == 'github' and (policy.git_access == 'none' or (
                policy.git_access != 'write' and tool_permission(name, read_only=read_only) == 'connections.write'
            )):
                raise HTTPException(403, 'Managed Git access is disabled by the session security policy.')
            return principal

    async def connection(self, scope, grant, *, write=False):
        async with self.database.sessions.begin() as db:
            await self.principal(db, scope.product_grant, 'connections.write' if write else 'connections.read')
            policy = await self.policy(db, scope.session_id)
            if policy.connected_apps is not None and grant.kind not in policy.connected_apps:
                raise HTTPException(403, 'This connection is disabled by the session security policy.')
            if grant.kind == 'github' and (policy.git_access == 'none' or write and policy.git_access != 'write'):
                raise HTTPException(403, 'Managed Git access is disabled by the session security policy.')

    async def tools(self, scope, definitions):
        from app.permissions import connector_tool, tool_permission
        async with self.database.sessions.begin() as db:
            principal = await self.principal(db, scope.product_grant)
            policy = await self.policy(db, scope.session_id)
            allowed = []
            for name, read_only in definitions:
                permission = tool_permission(name, read_only=read_only)
                connector = connector_tool(name)
                provider, operation = connector if connector else (None, name)
                aliases = {name, operation, f'{provider}_{operation}' if provider else name}
                if permission not in principal.effective_permissions:
                    continue
                if policy.tools is not None and not aliases.intersection(policy.tools):
                    continue
                if provider and policy.connected_apps is not None and provider not in policy.connected_apps:
                    continue
                if provider == 'github' and (policy.git_access == 'none' or policy.git_access != 'write' and permission == 'connections.write'):
                    continue
                allowed.append(name)
            return allowed

    @asynccontextmanager
    async def _snapshot(self, db=None):
        if db is not None:
            yield db
        else:
            async with self.database.sessions.begin() as snapshot:
                yield snapshot

    async def check_model(self, scope, *, db=None):
        from app.spend_limits import evaluate, limits_from_rows

        from .inference_usage import InferenceUsage
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            self.require_provider(await self.policy(transaction, scope.session_id))
            # Serialize the check and durable admission. Once a request is
            # pending, its unknown final cost blocks other budgeted requests.
            await transaction.execute(text('SELECT pg_advisory_xact_lock(726942, CAST(CAST(:schema AS regnamespace) AS oid)::int)'),
                             {'schema': self.identity.schema})
            rows = (await transaction.execute(text(f'SELECT id,limit_usd FROM {self.identity._table("spend_limits")}'))).mappings().all()
            limits = limits_from_rows(rows, principal.email)
            if limits.unlimited:
                return
            since = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
            usage = {}
            for kind in ('organization', 'user', 'session'):
                if getattr(limits, kind) is None:
                    continue
                query = select(func.coalesce(func.sum(cast(InferenceUsage.cost_usd, Numeric)), 0))
                unknown = select(func.count()).select_from(InferenceUsage).where(InferenceUsage.cost_usd.is_(None))
                clauses = [InferenceUsage.status != 'not_dispatched']
                if kind == 'session':
                    # A child shares every ancestor's session budget. Each
                    # ancestor's total includes all its delegated descendants.
                    ancestors = list(await transaction.scalars(text('''WITH RECURSIVE ancestors(id) AS (
                        SELECT CAST(:session AS text) UNION
                        SELECT p.inherited_from FROM moyai_product_session_policies p
                        JOIN ancestors a ON p.session_id=a.id WHERE p.inherited_from IS NOT NULL
                    ) SELECT id FROM ancestors'''), {'session': scope.session_id}))
                    amounts = []
                    for ancestor in ancestors:
                        family = text('''WITH RECURSIVE family(id) AS (
                            SELECT CAST(:ancestor AS text) UNION
                            SELECT p.session_id FROM moyai_product_session_policies p
                            JOIN family f ON p.inherited_from=f.id
                        ) SELECT id FROM family''').bindparams(ancestor=ancestor)
                        selected = [*clauses, InferenceUsage.session_id.in_(family)]
                        if await transaction.scalar(unknown.where(*selected)):
                            amounts.append(None)
                        else:
                            amounts.append(await transaction.scalar(query.where(*selected)))
                    usage[kind] = None if None in amounts else max(amounts)
                    continue
                clauses.append(InferenceUsage.created_at >= since)
                if kind == 'user':
                    actors = select(text('id')).select_from(text(self.identity._table('users'))).where(text('email=:email')).params(email=principal.email)
                    clauses.append(InferenceUsage.actor_id.in_(actors) if principal.email else InferenceUsage.actor_id == principal.id)
                pending = await transaction.scalar(unknown.where(*clauses))
                usage[kind] = None if pending else await transaction.scalar(query.where(*clauses))
            if evaluate(limits, usage):
                raise HTTPException(403, 'The configured spend limit has been reached. Ask a spend manager to review it.')

    async def workflow(self, db, principal, definition, *, previous='', scope=None):
        from app.security_profiles import intersect
        principal.require('automations.manage')
        selected = definition.security_profile_id
        if selected != previous:
            principal.require('security.manage')
        binding = await db.run_sync(lambda sync: self.product.profiles.resolve_for_new_session_in(
            CanonicalRead(sync, self.identity), selected))
        self.require_provider(binding.policy)
        if binding.policy.connected_apps is not None and not set(definition.plugins) <= set(binding.policy.connected_apps):
            raise HTTPException(403, 'The workflow connections exceed its security policy.')
        if definition.repo_url and (binding.policy.git_access == 'none' or (
                binding.policy.connected_apps is not None and 'github' not in binding.policy.connected_apps)):
            raise HTTPException(403, 'The workflow repository exceeds its security policy.')
        if scope is not None and intersect(await self.policy(db, scope.session_id), binding.policy) != binding.policy:
            raise HTTPException(403, 'A workflow cannot exceed the security policy of its creating session.')


def permission_for_user(user, permission):
    from app.permissions import BUILTIN_PERMISSIONS
    held = getattr(user, 'governance_permissions', None)
    return permission in (held if held is not None else BUILTIN_PERMISSIONS[user.role])
