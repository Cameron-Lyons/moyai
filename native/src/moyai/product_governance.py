"""Live canonical governance on the native admission and execution transactions."""
from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

from fastapi import HTTPException
from sqlalchemy import Numeric, and_, cast, exists, false, func, literal, not_, or_, select, text

from .product_governance_models import ProductSessionPolicy
from .product_identity import ROLE_REFUSAL

if TYPE_CHECKING:
    from app.spend_limits import SpendLimitSet

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


def month_period(now: datetime | None = None) -> tuple[str, str]:
    """The current UTC calendar month as (start, next month's start) ISO timestamps."""
    start = (now or datetime.now(UTC)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), (start + timedelta(days=32)).replace(day=1).isoformat()


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
        self.period_start = month_period(now)[0]
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


@dataclass(frozen=True)
class SpendState:
    """One person's limits and the usage admission compares with them.

    usage holds only the limited scopes, as USD Decimal totals, or None while a
    finished request's cost can still be recovered (which fails closed).
    """
    limits: SpendLimitSet
    usage: dict[str, Any] = field(default_factory=dict)


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
    from app.governance_audit import event_id, event_values, timestamp
    values = dict(zip(('action', 'actor', 'resource_type', 'resource_id', 'details'),
                      event_values(action, actor, resource_type, resource_id, details)))
    await db.execute(text(
        f"INSERT INTO {identity._table('governance_audit_events')} "
        '(id,action,actor,resource_type,resource_id,details,created_at) '
        'VALUES (:id,:action,:actor,:resource_type,:resource_id,:details,:created_at) ON CONFLICT (id) DO NOTHING'
    ), {**values, 'id': event_id(action, key), 'created_at': timestamp()})


MODEL_REFUSAL = 'This model is not allowed by the session security policy.'
REPOSITORY_REFUSAL = 'The repository exceeds the session security policy.'


# Refusals whose subject is an identifier (a connection kind or workflow id), so
# it can name the resource outside a session. A tool name or model id may be
# free-form: only its details keep it, as a digest unless it is an identifier.
NAMED_SUBJECTS = frozenset({'policy.connection_denied', 'policy.workflow_denied', 'policy.continuation_denied'})


@dataclass(frozen=True)
class Denial:
    """Where a check runs: the policy.* action a refusal records, its actor and scope.

    subject names what was refused (a tool, model, connection kind or workflow).
    Within a turn, one (action, session, turn, subject, reason) is recorded once,
    which collapses the governance_tool check and the activity interceptor,
    Temporal attempts and workflow resets. Outside a turn the key adds the actor
    and the minute, which bounds a client that repeats a refused request.
    """
    action: str
    actor_id: str
    session_id: str = ''
    turn_id: str = ''
    subject: str = ''

    @property
    def resource_id(self):
        """The session, else an identifier subject (NAMED_SUBJECTS), else the workspace."""
        if self.session_id:
            return self.session_id
        return self.subject if self.subject and self.action in NAMED_SUBJECTS else 'workspace'

    def key(self, reason):
        from app.governance_activity import minute_bucket
        if self.turn_id:
            return self.session_id, self.turn_id, self.subject, reason
        return self.actor_id, self.session_id, self.subject, reason, minute_bucket()


class ProductGovernance:
    def __init__(self, product: Any, database: Any, activity: Any = None):
        self.product, self.database = product, database
        self.identity = product.identity
        # moyai.product_activity_audit.ProductActivityAudit; None records no activity.
        self.activity = activity

    async def _refuse(self, denial, reason, detail, status=403, /, **details):
        """The refusal to raise, unchanged, after recording it once.

        The record is detached and fails open, and successful checks never
        reach it, so it adds no round trip to an allowed tool or model call.
        Its resource is Denial.resource_id.
        """
        if self.activity is not None:
            await self.activity.refused(
                denial.action, actor_id=denial.actor_id, resource_id=denial.resource_id,
                session_id=denial.session_id, details={'reason': reason, **details}, key=denial.key(reason))
        return HTTPException(status, detail)

    async def record(self, db, action, **event):
        """Record session or message activity in the caller's transaction (fails closed)."""
        if self.activity is not None:
            await self.activity.record(db, action, **event)

    async def record_message(self, db, actor_id, session_id, turn_id, *, origin, mode, model, grants,
                             reply=False, steering=False, attachments=0):
        """message.submitted for one turn: metadata only, never the prompt, title or file names."""
        from app.governance_activity import model_fields
        await self.record(db, 'message.submitted', actor_id=actor_id, resource_id=turn_id, session_id=session_id,
                          key=(turn_id,), details={
                              'origin': origin, 'mode': mode, 'reply': reply, 'steering': steering,
                              **model_fields(model), 'attachments': attachments,
                              'connection_kinds': sorted({grant.kind for grant in grants})})

    async def require(self, principal, permission, denial, /, **details):
        """principal.require, recording the refusal with its status and message unchanged."""
        if permission not in principal.effective_permissions:
            raise await self._refuse(denial, 'role_permission', ROLE_REFUSAL, permission=permission, **details)

    async def principal(self, db, grant, permission='sessions.create', *, action='policy.admission_denied',
                        session_id='', turn_id='', subject='', details=None):
        """The admitted principal; a missing permission records action with these details."""
        principal = await self.identity.authorize_admission(db, grant)
        await self.require(principal, permission, Denial(action, principal.id, session_id, turn_id, subject),
                           **(details or {}))
        return principal

    async def bind(self, db, session, principal, requested='', inherited_from=None, trusted_profile=False, ceiling=None,
                   *, origin='user', turn_id=''):
        """Pin a new session's policy; origin is how it was created, for its session.created event.

        A refusal names the parent session, if any: the new one never exists.
        """
        from app.security_profiles import dump_policy, intersect
        denial = Denial('policy.binding_denied', principal.id, inherited_from or '', turn_id)
        await self.require(principal, 'sessions.create', denial)
        if requested and not trusted_profile:
            await self.require(principal, 'security.manage', denial)
        existing = await db.get(ProductSessionPolicy, session.id)
        if existing is not None:
            return existing
        parent = await db.get(ProductSessionPolicy, inherited_from) if inherited_from else None
        if inherited_from and not requested:
            await self.require(principal, 'sessions.read', denial)
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
        await self.require_provider(policy, self.database.settings.sandbox_provider, denial)
        await db.flush()
        row = ProductSessionPolicy(session_id=session.id, profile_id=binding.profile_id,
                                   profile_revision=binding.revision, policy=dump_policy(policy),
                                   inherited_from=inherited_from,
                                   # An unbound parent (a pre-governance session) heads the family.
                                   family_root=parent.family_root if parent else inherited_from or session.id)
        db.add(row)
        await db.flush()
        # The mandatory policy read above already narrows this one, so it is the
        # session's effective policy for the rest of this transaction.
        self._remember(db, session.id, policy, row.family_root)
        await self.record(db, 'session.created', actor_id=principal.id, resource_id=session.id,
                          session_id=session.id, key=(session.id,), details={
                              'origin': origin, 'visibility': session.visibility,
                              'profile_id': binding.profile_id or None, 'profile_revision': binding.revision,
                              'inherited': inherited_from is not None})
        return row

    # Effective policies and family roots of bound sessions, and the mandatory
    # profile, per root transaction. Bindings are immutable, and the shared gate
    # callers take through principal() keeps mandatory-profile writers out until
    # the transaction ends, so a repeat read in one transaction is the same value.
    _policies: WeakKeyDictionary[Any, dict[str, Any]] = WeakKeyDictionary()

    def _memo(self, db):
        """This transaction's memo; {} (discarded) before the transaction begins."""
        transaction = db.sync_session.get_transaction()
        return {} if transaction is None else self._policies.setdefault(transaction, {})

    def _remember(self, db, session_id, policy, family_root):
        memo = self._memo(db)
        memo[session_id], memo['\0root:' + session_id] = policy, family_root

    async def policy(self, db, session_id):
        from app.security_profiles import ProfilePolicy, effective, load_policy
        # The memo first: the identity map holds a binding row only weakly, so
        # another get would read it again.
        if session_id in (memo := self._memo(db)):
            return memo[session_id]
        row = await db.get(ProductSessionPolicy, session_id)
        memo = self._memo(db)  # The get began the transaction if it had not begun.
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
            self._remember(db, session_id, policy, row.family_root)
        return policy

    async def family_root(self, db, session_id):
        """The root of the session's delegation family; itself when unbound."""
        if (root := self._memo(db).get('\0root:' + session_id)) is not None:
            return root
        bound = await db.get(ProductSessionPolicy, session_id)
        return bound.family_root if bound else session_id

    async def require_provider(self, policy, provider, denial, /, **details):
        """Refuse a network restriction where the session's computer cannot enforce it.

        Modal enforces it at computer creation (modal_network) once an operator
        sets MOYAI_NETWORK_POLICY_ENFORCEMENT=modal. The setting only decides
        admission: a computer is always created under its session's plan.
        """
        if policy.network_domains is None:
            return
        if provider == 'lambda':
            message = 'Lambda computers cannot enforce a network allowlist. Select a policy without network restrictions or use a Modal computer.'
        elif provider != 'modal':
            message = 'This computer provider cannot enforce a network allowlist. Select a policy without network restrictions.'
        elif self.database.settings.network_policy_enforcement != 'modal':
            message = 'This deployment cannot enforce network allowlists yet. Select a policy without network restrictions, or ask an operator to turn on Modal network enforcement.'
        else:
            return
        raise await self._refuse(denial, 'network_unenforceable', message, 409, **details)

    def provider_of(self, workspace):
        """The provider of a session's stored computer, or the deployment default before it has one."""
        reference = json.loads(workspace) if workspace else None
        return reference.get('provider') if reference else self.database.settings.sandbox_provider

    async def computer_provider(self, db, session_id):
        from .models import Session
        session = await db.get(Session, session_id)
        return self.provider_of(session.workspace if session else None)

    async def require_session_provider(self, db, policy, session_id, denial, /, **details):
        """require_provider for the session's computer; its provider is read only under a restriction."""
        if policy.network_domains is not None:
            await self.require_provider(policy, await self.computer_provider(db, session_id), denial, **details)

    async def network_plan(self, session_id, *, db=None):
        """The plan the session's Modal computers are created and checked under (see modal_network)."""
        from .modal_network import NetworkPlan
        async with self._snapshot(db) as transaction:
            policy = await self.policy(transaction, session_id)
        return NetworkPlan.of(policy.network_domains, session_id)

    async def admission(self, db, session, principal, grants=(), *, turn_id=''):
        denial = Denial('policy.admission_denied', principal.id, session.id, turn_id)
        await self.require(principal, 'sessions.create', denial)
        policy = await self.policy(db, session.id)
        # An existing computer keeps its provider when the deployment default changes.
        await self.require_provider(policy, self.provider_of(session.workspace), denial)
        kinds = sorted({grant.kind for grant in grants})
        if not all(self.admits(policy, grant.kind) for grant in grants):
            raise await self._refuse(denial, 'connection_disabled',
                                     'A selected connection is disabled by the session security policy.',
                                     connection_kinds=kinds)
        # authorize_scope runs this on every tool and activity authorization, so
        # a narrower mandatory repository limit also stops running sessions.
        if not all(self.admits_grant(policy, grant.kind, self.repository_of(grant)) for grant in grants):
            raise await self._refuse(denial, 'repository_policy',
                                     'A selected GitHub repository is not allowed by the session security policy.',
                                     connection_kinds=kinds)
        if grants:
            await self.require(principal, 'connections.read', denial)
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

    async def _require_model(self, policy, model, denial, *, reason='model_policy', message=MODEL_REFUSAL):
        from app.governance_activity import model_fields
        if not self.admits_model(policy, model):
            details = {'automation_id': denial.subject or None} if denial.action == 'policy.workflow_denied' \
                else model_fields(model)
            raise await self._refuse(denial, reason, message, **details)

    async def require_model(self, policy, model, *, actor_id, session_id='', turn_id=''):
        """Refuse a model the session policy does not allow."""
        await self._require_model(policy, model, Denial('policy.model_denied', actor_id, session_id, turn_id, model))

    async def session_model(self, policy, requested, default, available, *, actor_id):
        """A new session's model under its bound policy.

        An explicit request must be allowed. Otherwise the default is used when
        allowed, else the first allowed model in the workspace's order. A
        refusal names no session: the new one never exists.
        """
        if requested:
            await self.require_model(policy, requested, actor_id=actor_id)
            return requested
        if (allowed := self.implicit_model(policy, default, available)) is None:
            raise await self._refuse(
                Denial('policy.model_denied', actor_id), 'no_allowed_model',
                'No model enabled for this workspace is allowed by the session security policy.')
        return allowed

    @staticmethod
    def implicit_model(policy, default, available):
        """The default when allowed, else the first allowed model in the workspace's order, else None."""
        if ProductGovernance.admits_model(policy, default):
            return default
        return next((model for model in available if model in policy.models), None)

    @staticmethod
    def _connection_refusal(policy, kind, *, write=False):
        """(reason, message) when this policy refuses a connection of this kind, or None."""
        if policy.connected_apps is not None and kind not in policy.connected_apps:
            return 'connection_disabled', 'This connection is disabled by the session security policy.'
        if kind == 'github' and (policy.git_access == 'none' or write and policy.git_access != 'write'):
            return 'git_access', 'Managed Git access is disabled by the session security policy.'
        return None

    @staticmethod
    def connection_denial(policy, kind, *, write=False):
        """Why this policy refuses a connection of this kind, or None."""
        refusal = ProductGovernance._connection_refusal(policy, kind, write=write)
        return refusal and refusal[1]

    async def workspace(self, db, scope, context):
        principal = await self.principal(db, scope.product_grant, action='policy.workspace_denied',
                                         session_id=scope.session_id, turn_id=scope.turn_id)
        denial = Denial('policy.workspace_denied', principal.id, scope.session_id, scope.turn_id)
        if context.get('environment_build_id'):
            await self.require(principal, 'environments.read', denial)
        if not context.get('repo_url') and not context.get('repository_id'):
            return
        policy = await self.policy(db, scope.session_id)
        if context.get('repo_url'):
            await self.require(principal, 'connections.read', denial)
            if not self.admits(policy, 'github'):
                raise await self._refuse(denial, 'connection_disabled', REPOSITORY_REFUSAL)
        # An environment snapshot already contains its repository, and
        # repository preparation skips it, so the recorded ID is checked here.
        if not self.admits_repository(policy, context.get('repository_id')):
            raise await self._refuse(denial, 'repository_policy', REPOSITORY_REFUSAL)

    async def repository(self, scope, repository_id, *, db=None):
        """Refuse a repository checkout the session policy does not allow, before any provider read."""
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant, action='policy.workspace_denied',
                                             session_id=scope.session_id, turn_id=scope.turn_id)
            policy = await self.policy(transaction, scope.session_id)
            if not self.admits(policy, 'github') or not self.admits_repository(policy, repository_id):
                raise await self._refuse(
                    Denial('policy.workspace_denied', principal.id, scope.session_id, scope.turn_id),
                    'connection_disabled' if not self.admits(policy, 'github') else 'repository_policy',
                    REPOSITORY_REFUSAL)

    @staticmethod
    def _tool_denial(principal, policy, name, read_only):
        """(reason, message, details) when the principal and policy refuse one tool call, or None."""
        from app.permissions import connector_tool, tool_permission
        permission = tool_permission(name, read_only=read_only)
        provider, operation = connector_tool(name) or (None, name)
        if permission not in principal.effective_permissions:
            return 'role_permission', ROLE_REFUSAL, {'permission': permission, 'provider': provider}
        aliases = {name, operation, f'{provider}_{operation}' if provider else name}
        if policy.tools is not None and not aliases.intersection(policy.tools):
            return 'tool_disabled', 'This tool is disabled by the session security policy.', {'provider': provider}
        if provider and (refusal := ProductGovernance._connection_refusal(
                policy, provider, write=permission == 'connections.write')):
            return *refusal, {'provider': provider, 'permission': permission}
        return None

    async def check_tool(self, scope, name, *, read_only=None, db=None):
        from app.governance_activity import tool_fields
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant, action='policy.tool_denied',
                                             session_id=scope.session_id, turn_id=scope.turn_id, subject=name,
                                             details=tool_fields(name))
            denial = Denial('policy.tool_denied', principal.id, scope.session_id, scope.turn_id, name)
            policy = await self.policy(transaction, scope.session_id)
            await self.require_session_provider(transaction, policy, scope.session_id, denial, **tool_fields(name))
            if refusal := self._tool_denial(principal, policy, name, read_only):
                reason, message, details = refusal
                raise await self._refuse(denial, reason, message, **tool_fields(name), **details)
            return principal

    async def connection(self, scope, grant, *, write=False):
        async with self.database.sessions.begin() as db:
            principal = await self.principal(
                db, scope.product_grant, 'connections.write' if write else 'connections.read',
                action='policy.connection_denied', session_id=scope.session_id, turn_id=scope.turn_id,
                subject=grant.kind, details={'kind': grant.kind, 'write': write})
            denial = Denial('policy.connection_denied', principal.id, scope.session_id, scope.turn_id, grant.kind)
            policy = await self.policy(db, scope.session_id)
            if refusal := self._connection_refusal(policy, grant.kind, write=write):
                raise await self._refuse(denial, *refusal, kind=grant.kind, write=write)
            if not self.admits_grant(policy, grant.kind, self.repository_of(grant)):
                raise await self._refuse(denial, 'repository_policy',
                                         'This GitHub repository is not allowed by the session security policy.',
                                         kind=grant.kind, write=write)

    async def tools(self, scope, definitions, *, db=None):
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant,
                                             session_id=scope.session_id, turn_id=scope.turn_id)
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

    def _person(self, email, actor_id):
        """Ledger rows of every canonical actor with this email, or of one actor without an email."""
        from .inference_usage import InferenceUsage
        return InferenceUsage.actor_id.in_(
            select(text('id')).select_from(text(self.identity._table('users')))
            .where(text('email=:email')).params(email=email)) if email else InferenceUsage.actor_id == actor_id

    async def spend_state(self, db, principal, session_id: str | None = None) -> SpendState:
        """Limits and usage for one principal in db's snapshot; without session_id, no session scope.

        Admission and the personal status share it. One canonical statement
        reads the limits, directory tiers included; each limited scope then
        adds one ledger sum (_spent), and nothing is written.
        """
        from app.spend_limits import SpendLimits

        from .inference_usage import InferenceUsage
        limits = await db.run_sync(lambda sync: SpendLimits.resolve_in(
            CanonicalRead(sync, self.identity), principal.email))
        if limits.unlimited:
            return SpendState(limits)
        ledger = SpendLedger(self.database)
        month = InferenceUsage.created_at >= ledger.period_start
        scopes = {'organization': [month], 'user': [month, self._person(principal.email, principal.id)]}
        if session_id is not None and limits.session is not None:
            # policy() has already memoized this during admission.
            root = await self.family_root(db, session_id)
            # A delegated child shares every ancestor's lifetime session
            # budget. The whole family's total is the largest one that any
            # ancestor's limit sees, so every member is checked against it.
            # IN over a union keeps both lookups indexed; an OR would scan the ledger.
            scopes['session'] = [InferenceUsage.session_id.in_(select(ProductSessionPolicy.session_id).where(
                ProductSessionPolicy.family_root == root).union_all(select(literal(root))))]
        usage = {}
        for kind, clauses in scopes.items():
            if getattr(limits, kind) is not None:
                usage[kind] = await self._spent(db, ledger, *clauses)
        return SpendState(limits, usage)

    @staticmethod
    async def _spent(db, ledger, *clauses):
        """Ledger spend matching clauses as admission counts it; None while a cost is awaited."""
        total, awaiting = (await db.execute(select(ledger.spent, ledger.awaiting).where(*clauses))).one()
        return None if awaiting else total

    async def month_spend(self, db, email):
        """A person's month-to-date spend, the sum spend_state reads for their monthly limit.

        The limit lookup reads it whether or not a limit applies, which spend_state skips.
        """
        from .inference_usage import InferenceUsage
        ledger = SpendLedger(self.database)
        return await self._spent(db, ledger, InferenceUsage.created_at >= ledger.period_start, self._person(email, ''))

    async def check_model(self, scope, *, model, db=None):
        """Admit one paid request for this model: the session policy, then spend limits."""
        from app.governance_activity import model_fields
        from app.spend_limits import SpendLimitReached, evaluation, refusal
        async with self._snapshot(db) as transaction:
            principal = await self.principal(transaction, scope.product_grant, action='policy.model_denied',
                                             session_id=scope.session_id, turn_id=scope.turn_id, subject=model,
                                             details=model_fields(model))
            denial = Denial('policy.model_denied', principal.id, scope.session_id, scope.turn_id, model)
            policy = await self.policy(transaction, scope.session_id)
            await self.require_session_provider(transaction, policy, scope.session_id, denial, **model_fields(model))
            # Before the spend lookup, which returns early when nothing is limited.
            await self._require_model(policy, model, denial)
            state = await self.spend_state(transaction, principal, scope.session_id)
            if (reason := refusal(state.limits, state.usage)) is not None:
                refused = SpendLimitReached(reason)
                exceeded, pending = evaluation(state.limits, state.usage)
                # Scopes only: no amounts, limits or receipts.
                await self._refuse(denial, 'spend_limit', refused.detail, **model_fields(model),
                                   scopes=exceeded, awaiting_cost=bool(pending))
                raise refused

    async def profile_policy(self, db, requested=''):
        """The policy a new session would bind under this profile ('' is the default), mandatory included."""
        binding = await db.run_sync(lambda sync: self.product.profiles.resolve_for_new_session_in(
            CanonicalRead(sync, self.identity), requested))
        return binding.policy

    async def new_session_policy(self, db, principal, requested=''):
        """The policy and implicit model of a new session under this profile, for model and connection pickers.

        Selecting a profile needs security.manage, as in bind(). The model is the
        one session_model gives a session that does not ask for one; None when
        the policy allows no enabled model. Admission still decides, so this
        probe records nothing.
        """
        principal.require('sessions.create')
        if requested:
            principal.require('security.manage')
        policy = await self.profile_policy(db, requested)
        settings = self.database.settings
        return policy, self.implicit_model(policy, settings.default_model, settings.models)

    async def workflow(self, db, principal, definition, *, previous='', scope=None, model, automation_id=''):
        """Check a workflow definition against its profile; model is its resolved model choice."""
        from app.security_profiles import intersect
        denial = Denial('policy.workflow_denied', principal.id, scope.session_id if scope else '',
                        scope.turn_id if scope else '', automation_id)
        workflow = {'automation_id': automation_id or None}
        await self.require(principal, 'automations.manage', denial, **workflow)
        selected = definition.security_profile_id
        if selected != previous:
            await self.require(principal, 'security.manage', denial, **workflow)
        policy = await self.profile_policy(db, selected)
        await self.require_provider(policy, self.database.settings.sandbox_provider, denial, **workflow)

        async def refuse(reason, message):
            return await self._refuse(denial, reason, message, **workflow)
        if not all(self.admits(policy, kind) for kind in definition.plugins) or (
                'github' in definition.plugins and policy.repositories == ()):
            raise await refuse('connection_policy', 'The workflow connections exceed its security policy.')
        if definition.repo_url and not self.admits(policy, 'github'):
            raise await refuse('connection_policy', 'The workflow repository exceeds its security policy.')
        if message := self.workflow_repository_denial(policy, definition):
            raise await refuse('repository_policy', message)
        await self._require_model(policy, model, denial, message='The workflow model exceeds its security policy.')
        if scope is not None and intersect(await self.policy(db, scope.session_id), policy) != policy:
            raise await refuse('exceeds_session', 'A workflow cannot exceed the security policy of its creating session.')

    async def continuation_wider(self, db, session_id, requested='', *, policy=None):
        """Whether the chat allows more than the workflow profile; a probe that records nothing.

        policy is the requested profile's policy when the caller already resolved it.
        """
        from app.security_profiles import intersect
        if policy is None:
            policy = await self.profile_policy(db, requested)
        current = await self.policy(db, session_id)
        return intersect(current, policy) != current

    async def continuation(self, db, session_id, requested='', *, actor_id='', automation_id='', model=None):
        """Admit a run in an existing chat only while the chat is no wider than its workflow.

        A chat's binding is immutable, so it cannot adopt the workflow's profile.
        With model (the workflow's resolved model), also refuse a model the
        chat's policy does not allow, which would otherwise refuse every run.
        """
        from app.governance_activity import model_fields
        denial = Denial('policy.continuation_denied', actor_id, session_id, subject=automation_id)
        if await self.continuation_wider(db, session_id, requested):
            raise await self._refuse(
                denial, 'continuation_wider', 'This chat allows more than the workflow security policy. '
                                              'Choose a chat started under that policy, or a new chat for each run.',
                automation_id=automation_id or None)
        if model is not None and not self.admits_model(await self.policy(db, session_id), model):
            raise await self._refuse(
                denial, 'model_policy', "The chat's security policy does not allow the workflow model. "
                                        'Choose a model it allows, or a new chat for each run.',
                automation_id=automation_id or None, **model_fields(model))


def permission_for_user(user, permission):
    from app.permissions import BUILTIN_PERMISSIONS
    held = getattr(user, 'governance_permissions', None)
    if held is None:
        held = getattr(user, 'effective_permissions', None)
    return permission in (held if held is not None else BUILTIN_PERMISSIONS[user.role])
