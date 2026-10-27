"""Live canonical governance on the native admission and execution transactions."""
from __future__ import annotations

import hashlib
import json
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


async def record_runtime_event(db, identity, key, action, actor, resource_type, resource_id, details=None):
    """Insert one canonical governance audit event in a native transaction, once per key.

    The event commits or rolls back with the native outcome it records, as
    product_skill_tools' canonical skill_audit rows do. Its id derives from the
    action and key, so a retried activity reaching the same outcome adds nothing.
    """
    from app.governance_audit import event_values, timestamp
    values = dict(zip(('action', 'actor', 'resource_type', 'resource_id', 'details'),
                      event_values(action, actor, resource_type, resource_id, details)))
    await db.execute(text(
        f"INSERT INTO {identity._table('governance_audit_events')} "
        '(id,action,actor,resource_type,resource_id,details,created_at) '
        'VALUES (:id,:action,:actor,:resource_type,:resource_id,:details,:created_at) ON CONFLICT (id) DO NOTHING'
    ), {**values, 'id': hashlib.sha256(f'{action}/{key}'.encode()).hexdigest()[:32], 'created_at': timestamp()})


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
        self.require_provider(policy, self.database.settings.sandbox_provider)
        await db.flush()
        row = ProductSessionPolicy(session_id=session.id, profile_id=binding.profile_id,
                                   profile_revision=binding.revision, policy=dump_policy(policy),
                                   inherited_from=inherited_from,
                                   # An unbound parent (a pre-governance session) heads the family.
                                   family_root=parent.family_root if parent else inherited_from or session.id)
        db.add(row)
        await db.flush()
        return row

    # Effective policies of bound sessions, and the mandatory profile, per root
    # transaction. Bindings are immutable, and the shared gate callers take
    # through principal() keeps mandatory-profile writers out until the
    # transaction ends, so a repeat read in one transaction is the same value.
    _policies: WeakKeyDictionary[Any, dict[str, Any]] = WeakKeyDictionary()

    async def policy(self, db, session_id):
        from app.security_profiles import ProfilePolicy, effective, load_policy
        row = await db.get(ProductSessionPolicy, session_id)
        transaction = db.sync_session.get_transaction()
        memo = {} if transaction is None else self._policies.setdefault(transaction, {})
        if session_id in memo:
            return memo[session_id]
        if '\0mandatory' not in memo:
            memo['\0mandatory'] = await db.run_sync(lambda sync: self.product.profiles.mandatory_in(
                CanonicalRead(sync, self.identity)))
        mandatory = memo['\0mandatory']
        # Sessions predating the migration had no selected profile. The live
        # mandatory policy still applies to these historical sessions.
        policy = effective(load_policy(row.policy) if row else ProfilePolicy(),
                           mandatory.policy if mandatory else None)
        # bind() may still pin an unbound session later in this transaction.
        if row is not None:
            memo[session_id] = policy
        return policy

    def require_provider(self, policy, provider):
        """Refuse a network restriction where the session's computer cannot enforce it.

        Modal enforces it at computer creation (modal_network) once an operator
        sets MOYAI_NETWORK_POLICY_ENFORCEMENT=modal. The setting only decides
        admission: a computer is always created under its session's plan.
        """
        if policy.network_domains is None:
            return
        if provider == 'lambda':
            raise HTTPException(409, 'Lambda computers cannot enforce a network allowlist. Select a policy without network restrictions or use a Modal computer.')
        if provider != 'modal':
            raise HTTPException(409, 'This computer provider cannot enforce a network allowlist. Select a policy without network restrictions.')
        if self.database.settings.network_policy_enforcement != 'modal':
            raise HTTPException(409, 'This deployment cannot enforce network allowlists yet. Select a policy without network restrictions, or ask an operator to turn on Modal network enforcement.')

    def provider_of(self, workspace):
        """The provider of a session's stored computer, or the deployment default before it has one."""
        reference = json.loads(workspace) if workspace else None
        return reference.get('provider') if reference else self.database.settings.sandbox_provider

    async def computer_provider(self, db, session_id):
        from .models import Session
        session = await db.get(Session, session_id)
        return self.provider_of(session.workspace if session else None)

    async def require_session_provider(self, db, policy, session_id):
        """require_provider for the session's computer; its provider is read only under a restriction."""
        if policy.network_domains is not None:
            self.require_provider(policy, await self.computer_provider(db, session_id))

    async def network_plan(self, session_id, *, db=None):
        """The plan the session's Modal computers are created and checked under (see modal_network)."""
        from .modal_network import NetworkPlan
        async with self._snapshot(db) as transaction:
            policy = await self.policy(transaction, session_id)
        return NetworkPlan.of(policy.network_domains, session_id)

    async def admission(self, db, session, principal, grants=()):
        principal.require('sessions.create')
        policy = await self.policy(db, session.id)
        # An existing computer keeps its provider when the deployment default changes.
        self.require_provider(policy, self.provider_of(session.workspace))
        if not all(self.admits(policy, grant.kind) for grant in grants):
            raise HTTPException(403, 'A selected connection is disabled by the session security policy.')
        # authorize_scope runs this on every tool and activity authorization, so
        # a narrower mandatory repository limit also stops running sessions.
        if not all(self.admits_grant(policy, grant.kind, self.repository_of(grant)) for grant in grants):
            raise HTTPException(403, 'A selected GitHub repository is not allowed by the session security policy.')
        if grants:
            principal.require('connections.read')
        return policy

    @staticmethod
    def admits(policy, kind):
        """Whether a session under this policy may select a connection of this kind."""
        # A GitHub grant under no Git access would only fail every turn's tool
        # discovery, so it is refused with the other disallowed connections.
        return ProductGovernance.connection_denial(policy, kind) is None

    @staticmethod
    def repository_of(grant):
        """A GitHub grant's permanent repository ID, or None."""
        identity = (grant.policy.get('product') or {}).get('repository_id')
        return identity if type(identity) is int and identity > 0 else None

    @staticmethod
    def admits_repository(policy, repository_id):
        """Whether the policy allows this repository; under a limit a missing ID is refused."""
        return policy.repositories is None or (type(repository_id) is int and repository_id in policy.repositories)

    @staticmethod
    def admits_grant(policy, kind, repository_id):
        """admits() plus the repository limit for a GitHub grant.

        admits() stays kind-only, so kind-level callers such as workflow
        plugins do not refuse GitHub because a repository is unknown there.
        """
        return ProductGovernance.admits(policy, kind) and (
            kind != 'github' or ProductGovernance.admits_repository(policy, repository_id))

    @staticmethod
    def workflow_repository_denial(policy, definition):
        """Why this policy refuses a workflow's saved repository or a GitHub trigger repository, or None.

        workflow() refuses with it and the automation readiness review reports
        it, so both check the same repositories.
        """
        if (definition.repo_url or definition.github_repository_id) and not ProductGovernance.admits_repository(
                policy, definition.github_repository_id):
            return 'The workflow repository exceeds its security policy.'
        if not all(ProductGovernance.admits_repository(policy, trigger.event.repository_id)
                   for trigger in definition.triggers if trigger.event is not None and trigger.event.provider == 'github'):
            return 'A workflow trigger repository exceeds its security policy.'
        return None

    @staticmethod
    def admits_model(policy, model):
        """Whether the policy allows this model."""
        return policy.models is None or model in policy.models

    @staticmethod
    def require_model(policy, model, message='This model is not allowed by the session security policy.'):
        if not ProductGovernance.admits_model(policy, model):
            raise HTTPException(403, message)

    @staticmethod
    def session_model(policy, requested, default, available):
        """A new session's model under its bound policy.

        An explicit request must be allowed. Otherwise the default is used when
        allowed, else the first allowed model in the workspace's order.
        """
        if requested:
            ProductGovernance.require_model(policy, requested)
            return requested
        if ProductGovernance.admits_model(policy, default):
            return default
        allowed = next((model for model in available if model in policy.models), None)
        if allowed is None:
            raise HTTPException(403, 'No model enabled for this workspace is allowed by the session security policy.')
        return allowed

    @staticmethod
    def connection_denial(policy, kind, *, write=False):
        """Why this policy refuses a connection of this kind, or None."""
        if policy.connected_apps is not None and kind not in policy.connected_apps:
            return 'This connection is disabled by the session security policy.'
        if kind == 'github' and (policy.git_access == 'none' or write and policy.git_access != 'write'):
            return 'Managed Git access is disabled by the session security policy.'
        return None

    async def workspace(self, db, scope, context):
        principal = await self.principal(db, scope.product_grant)
        if context.get('environment_build_id'):
            principal.require('environments.read')
        if not context.get('repo_url') and not context.get('repository_id'):
            return
        policy = await self.policy(db, scope.session_id)
        if context.get('repo_url'):
            principal.require('connections.read')
            if not self.admits(policy, 'github'):
                raise HTTPException(403, 'The repository exceeds the session security policy.')
        # An environment snapshot already contains its repository, and
        # repository preparation skips it, so the recorded ID is checked here.
        if not self.admits_repository(policy, context.get('repository_id')):
            raise HTTPException(403, 'The repository exceeds the session security policy.')

    async def repository(self, scope, repository_id, *, db=None):
        """Refuse a repository checkout the session policy does not allow, before any provider read."""
        async with self._snapshot(db) as transaction:
            await self.principal(transaction, scope.product_grant)
            policy = await self.policy(transaction, scope.session_id)
            if not self.admits(policy, 'github') or not self.admits_repository(policy, repository_id):
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
        if provider:
            return ProductGovernance.connection_denial(policy, provider, write=permission == 'connections.write')
        return None

    async def check_tool(self, scope, name, *, read_only=None, db=None):
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            policy = await self.policy(transaction, scope.session_id)
            await self.require_session_provider(transaction, policy, scope.session_id)
            if denial := self._tool_denial(principal, policy, name, read_only):
                raise HTTPException(403, denial)
            return principal

    async def connection(self, scope, grant, *, write=False):
        async with self.database.sessions.begin() as db:
            await self.principal(db, scope.product_grant, 'connections.write' if write else 'connections.read')
            policy = await self.policy(db, scope.session_id)
            if denial := self.connection_denial(policy, grant.kind, write=write):
                raise HTTPException(403, denial)
            if not self.admits_grant(policy, grant.kind, self.repository_of(grant)):
                raise HTTPException(403, 'This GitHub repository is not allowed by the session security policy.')

    async def tools(self, scope, definitions, *, db=None):
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            policy = await self.policy(transaction, scope.session_id)
            return [name for name, read_only in definitions
                    if self._tool_denial(principal, policy, name, read_only) is None]

    @asynccontextmanager
    async def _snapshot(self, db=None):
        if db is not None:
            yield db
        else:
            async with self.database.sessions.begin() as snapshot:
                yield snapshot

    async def check_model(self, scope, *, model, db=None):
        """Admit one paid request for this model: the session policy, then spend limits."""
        from app.spend_limits import SpendLimits, evaluate

        from .inference_usage import InferenceUsage
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant)
            policy = await self.policy(transaction, scope.session_id)
            await self.require_session_provider(transaction, policy, scope.session_id)
            # Before the spend lookup, which returns early when nothing is limited.
            self.require_model(policy, model)
            limits = await transaction.run_sync(lambda sync: SpendLimits.resolve_in(
                CanonicalRead(sync, self.identity), principal.email))
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

    async def profile_policy(self, db, requested=''):
        """The policy a new session would bind under this profile ('' is the default), mandatory included."""
        binding = await db.run_sync(lambda sync: self.product.profiles.resolve_for_new_session_in(
            CanonicalRead(sync, self.identity), requested))
        return binding.policy

    async def new_session_policy(self, db, principal, requested=''):
        """The policy and implicit model of a new session under this profile, for model and connection pickers.

        Selecting a profile needs security.manage, as in bind(). The model is the
        one session_model gives a session that does not ask for one; None when
        the policy allows no enabled model. Admission still decides.
        """
        principal.require('sessions.create')
        if requested:
            principal.require('security.manage')
        policy = await self.profile_policy(db, requested)
        settings = self.database.settings
        try:
            model = self.session_model(policy, '', settings.default_model, settings.models)
        except HTTPException:
            model = None
        return policy, model

    async def workflow(self, db, principal, definition, *, previous='', scope=None, model):
        """Check a workflow definition against its profile; model is its resolved model choice."""
        from app.security_profiles import intersect
        principal.require('automations.manage')
        selected = definition.security_profile_id
        if selected != previous:
            principal.require('security.manage')
        policy = await self.profile_policy(db, selected)
        self.require_provider(policy, self.database.settings.sandbox_provider)
        if not all(self.admits(policy, kind) for kind in definition.plugins) or (
                'github' in definition.plugins and policy.repositories == ()):
            raise HTTPException(403, 'The workflow connections exceed its security policy.')
        if definition.repo_url and not self.admits(policy, 'github'):
            raise HTTPException(403, 'The workflow repository exceeds its security policy.')
        if denial := self.workflow_repository_denial(policy, definition):
            raise HTTPException(403, denial)
        self.require_model(policy, model, 'The workflow model exceeds its security policy.')
        if scope is not None and intersect(await self.policy(db, scope.session_id), policy) != policy:
            raise HTTPException(403, 'A workflow cannot exceed the security policy of its creating session.')

    async def continuation(self, db, session_id, requested='', *, policy=None):
        """Admit a run in an existing chat only while the chat is no wider than its workflow.

        A chat's binding is immutable, so it cannot adopt the workflow's profile.
        policy is the requested profile's policy when the caller already resolved it.
        """
        from app.security_profiles import intersect
        if policy is None:
            policy = await self.profile_policy(db, requested)
        current = await self.policy(db, session_id)
        if intersect(current, policy) != current:
            raise HTTPException(403, 'This chat allows more than the workflow security policy. '
                                     'Choose a chat started under that policy, or a new chat for each run.')


def permission_for_user(user, permission):
    from app.permissions import BUILTIN_PERMISSIONS
    held = getattr(user, 'governance_permissions', None)
    if held is None:
        held = getattr(user, 'effective_permissions', None)
    return permission in (held if held is not None else BUILTIN_PERMISSIONS[user.role])
