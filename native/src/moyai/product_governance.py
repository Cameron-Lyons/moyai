"""Live canonical governance on the native admission and execution transactions."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from weakref import WeakKeyDictionary

from fastapi import HTTPException
from sqlalchemy import Numeric, and_, cast, exists, false, func, literal, not_, or_, select, text

from .product_governance_models import ProductSessionPolicy

# A request without a reported cost stops blocking budgets after this long.
RECEIPT_WINDOW = timedelta(days=1)
# LiteLLM writes spend logs within seconds, so a receipt it still has not
# logged after this long is reported instead of blocking; recovery keeps trying.
MISSING_RECEIPT_WINDOW = timedelta(hours=1)
# A model activity ends at its timeout; this allows for its final ledger write.
IN_FLIGHT_MARGIN = timedelta(minutes=1)
# LiteLLM records a gateway error at zero spend, and a duplicate receipt's
# charge is already counted on the request that holds it.
UNBILLED = ('gateway_error', 'duplicate_provider_receipt')


class SpendLedger:
    """Spend predicates over the native inference ledger for admission and the spend page.

    spent sums reported costs. A pending request is in flight until the model
    timeout passes; it neither counts nor blocks. awaiting counts finished
    unpriced requests that receipt recovery can still settle, and any of them
    makes a limited scope fail closed. unresolved counts those recovery can no
    longer settle; they are reported for review instead of blocking.
    """

    def __init__(self, database):
        from .inference_usage import InferenceUsage as usage
        from .product_inference import ProductInferenceRequest as request
        now = datetime.now(UTC)
        self.period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        started = now - timedelta(seconds=database.settings.model_timeout_seconds) - IN_FLIGHT_MARGIN
        in_flight = and_(usage.status == 'pending', usage.created_at >= started.isoformat())
        unpriced = and_(usage.cost_usd.is_(None), usage.status != 'not_dispatched', not_(in_flight),
                        func.coalesce(usage.coverage_error, '').not_in(UNBILLED))
        recoverable = false()
        service = getattr(database, 'product_inference', None)
        if service is not None and service.settings.litellm_spend_recovery_enabled:
            gateway, key_hash = service.scope()
            # The requests ProductInferenceRecovery.poll still retries.
            recoverable = and_(usage.created_at >= (now - RECEIPT_WINDOW).isoformat(), exists().where(
                request.request_key == usage.request_key, request.gateway_scope == gateway,
                request.key_hash == key_hash,
                or_(request.next_attempt_at.is_not(None), request.recovery_error == 'receipt_access_denied'),
                or_(request.recovery_error.is_distinct_from('not_found'),
                    usage.created_at >= (now - MISSING_RECEIPT_WINDOW).isoformat())))
        self.spent = func.coalesce(func.sum(cast(usage.cost_usd, Numeric)), 0)
        self.awaiting = func.count().filter(unpriced, recoverable)
        self.unresolved = func.count().filter(unpriced, not_(recoverable))
        self.in_flight = func.count().filter(in_flight)


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
        parent = await db.get(ProductSessionPolicy, inherited_from) if inherited_from else None
        if inherited_from and not requested:
            principal.require('sessions.read')
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
                                   inherited_from=inherited_from,
                                   # An unbound parent (a pre-governance session) heads the family.
                                   family_root=parent.family_root if parent else inherited_from or session.id)
        db.add(row)
        await db.flush()
        return row

    # Effective policies of bound sessions, per root transaction. Bindings are
    # immutable, and the shared gate callers take through principal() keeps
    # mandatory-profile writers out until the transaction ends, so a repeat
    # read in one transaction is the same value.
    _policies: WeakKeyDictionary[Any, dict[str, Any]] = WeakKeyDictionary()

    async def policy(self, db, session_id):
        from app.security_profiles import ProfilePolicy, effective, load_policy
        row = await db.get(ProductSessionPolicy, session_id)
        # bind() may still pin an unbound session later in this transaction.
        transaction = db.sync_session.get_transaction() if row is not None else None
        memo = {} if transaction is None else self._policies.setdefault(transaction, {})
        if session_id not in memo:
            mandatory = await db.run_sync(lambda sync: self.product.profiles.mandatory_in(
                CanonicalRead(sync, self.identity)))
            # Sessions predating the migration had no selected profile. The live
            # mandatory policy still applies to these historical sessions.
            memo[session_id] = effective(load_policy(row.policy) if row else ProfilePolicy(),
                                         mandatory.policy if mandatory else None)
        return memo[session_id]

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
        if not all(self.admits(policy, grant.kind) for grant in grants):
            raise HTTPException(403, 'A selected connection is disabled by the session security policy.')
        if grants:
            principal.require('connections.read')
        return policy

    @staticmethod
    def admits(policy, kind):
        """Whether a session under this policy may select a connection of this kind."""
        # A GitHub grant under no Git access would only fail every turn's tool
        # discovery, so it is refused with the other disallowed connections.
        return (policy.connected_apps is None or kind in policy.connected_apps) and not (
            kind == 'github' and policy.git_access == 'none')

    async def workspace(self, db, scope, context):
        principal = await self.principal(db, scope.product_grant)
        if context.get('environment_build_id'):
            principal.require('environments.read')
        if context.get('repo_url'):
            principal.require('connections.read')
            policy = await self.policy(db, scope.session_id)
            if policy.git_access == 'none' or (policy.connected_apps is not None and 'github' not in policy.connected_apps):
                raise HTTPException(403, 'The repository exceeds the session security policy.')

    @staticmethod
    def _tool_denial(principal, policy, name, read_only):
        """Why the principal and policy refuse one tool call, or None when both allow it."""
        from app.permissions import connector_tool, tool_permission
        permission = tool_permission(name, read_only=read_only)
        provider, operation = connector_tool(name) or (None, name)
        if permission not in principal.effective_permissions:
            return 'Your workspace role does not allow this action.'
        aliases = {name, operation, f'{provider}_{operation}' if provider else name}
        if policy.tools is not None and not aliases.intersection(policy.tools):
            return 'This tool is disabled by the session security policy.'
        if provider and policy.connected_apps is not None and provider not in policy.connected_apps:
            return 'This connection is disabled by the session security policy.'
        if provider == 'github' and (
                policy.git_access == 'none' or policy.git_access != 'write' and permission == 'connections.write'):
            return 'Managed Git access is disabled by the session security policy.'
        return None

    async def check_tool(self, scope, name, *, read_only=None, db=None):
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            policy = await self.policy(transaction, scope.session_id)
            self.require_provider(policy)
            if denial := self._tool_denial(principal, policy, name, read_only):
                raise HTTPException(403, denial)
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
        async with self.database.sessions.begin() as db:
            principal = await self.principal(db, scope.product_grant)
            policy = await self.policy(db, scope.session_id)
            return [name for name, read_only in definitions
                    if self._tool_denial(principal, policy, name, read_only) is None]

    @asynccontextmanager
    async def _snapshot(self, db=None):
        if db is not None:
            yield db
        else:
            async with self.database.sessions.begin() as snapshot:
                yield snapshot

    async def check_model(self, scope, *, db=None):
        from app.spend_limits import evaluate, limit_ids, limits_from_rows

        from .inference_usage import InferenceUsage
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            self.require_provider(await self.policy(transaction, scope.session_id))
            rows = (await transaction.execute(
                text(f'SELECT id,limit_usd FROM {self.identity._table("spend_limits")} WHERE id = ANY(:ids)'),
                {'ids': list(limit_ids(principal.email))})).mappings().all()
            limits = limits_from_rows(rows, principal.email)
            if limits.unlimited:
                return
            ledger = SpendLedger(self.database)
            # policy() above has already loaded this binding.
            bound = await transaction.get(ProductSessionPolicy, scope.session_id)
            root = bound.family_root if bound else scope.session_id
            scopes = {
                'organization': [InferenceUsage.created_at >= ledger.period_start],
                'user': [InferenceUsage.created_at >= ledger.period_start, InferenceUsage.actor_id.in_(
                    select(text('id')).select_from(text(self.identity._table('users')))
                    .where(text('email=:email')).params(email=principal.email))
                    if principal.email else InferenceUsage.actor_id == principal.id],
                # A delegated child shares every ancestor's lifetime session
                # budget. The whole family's total is the largest one that any
                # ancestor's limit sees, so every member is checked against it.
                # IN over a union keeps both lookups indexed; an OR would scan the ledger.
                'session': [InferenceUsage.session_id.in_(select(ProductSessionPolicy.session_id).where(
                    ProductSessionPolicy.family_root == root).union_all(select(literal(root))))],
            }
            usage = {}
            for kind, clauses in scopes.items():
                if getattr(limits, kind) is not None:
                    total, awaiting = (await transaction.execute(
                        select(ledger.spent, ledger.awaiting).where(*clauses))).one()
                    usage[kind] = None if awaiting else total
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
        if not all(self.admits(binding.policy, kind) for kind in definition.plugins):
            raise HTTPException(403, 'The workflow connections exceed its security policy.')
        if definition.repo_url and (binding.policy.git_access == 'none' or (
                binding.policy.connected_apps is not None and 'github' not in binding.policy.connected_apps)):
            raise HTTPException(403, 'The workflow repository exceeds its security policy.')
        if scope is not None and intersect(await self.policy(db, scope.session_id), binding.policy) != binding.policy:
            raise HTTPException(403, 'A workflow cannot exceed the security policy of its creating session.')

    async def continuation(self, db, session_id, requested=''):
        """Admit a run in an existing chat only while the chat is no wider than its workflow.

        A chat's binding is immutable, so it cannot adopt the workflow's profile.
        """
        from app.security_profiles import intersect
        binding = await db.run_sync(lambda sync: self.product.profiles.resolve_for_new_session_in(
            CanonicalRead(sync, self.identity), requested))
        current = await self.policy(db, session_id)
        if intersect(current, binding.policy) != current:
            raise HTTPException(403, 'This chat allows more than the workflow security policy. '
                                     'Choose a chat started under that policy, or a new chat for each run.')


def permission_for_user(user, permission):
    from app.permissions import BUILTIN_PERMISSIONS
    held = getattr(user, 'governance_permissions', None)
    if held is None:
        held = getattr(user, 'effective_permissions', None)
    return permission in (held if held is not None else BUILTIN_PERMISSIONS[user.role])
