"""Native HTTP adapters for the canonical governance services."""
from __future__ import annotations

import asyncio
from typing import Literal

from app.config import MODEL_CATALOG
from app.enterprise_roles import GovernanceActor, GroupRoleChange, RoleAssignment, RoleCreate, RoleUpdate
from app.governance_audit import parse_filters
from app.permissions import BUILTIN_PERMISSIONS, catalog
from app.scim import TokenCreate
from app.security_profiles import ProfileDefaults, SaveProfile
from app.spend_limits import SpendLimitChanges
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from .product_governance_views import (
    AuditPage,
    CreatedScimToken,
    GovernanceGroupRole,
    GovernanceRole,
    GovernanceRoleAssignment,
    PermissionCatalog,
    RolesAdmin,
    ScimAdmin,
    ScimToken,
    SecurityProfileDefaults,
    SecurityProfilesAdmin,
    SecurityProfileView,
    SessionProfileCatalog,
    SessionSecurityPolicy,
    SpendLimitsAdmin,
)


def routes(runtime):
    product = runtime.product
    router = APIRouter()
    # The bearer-authenticated SCIM protocol (RFC 7644) is for identity
    # providers, not the generated frontend client.
    router.include_router(product.scim.router(), include_in_schema=False)

    async def principal(request: Request):
        return await product.identity.authenticate(request, mutation=request.method not in {'GET', 'HEAD'})

    def governed(user):
        return GovernanceActor.from_principal(user)

    @router.get('/api/permissions', operation_id='getPermissions')
    async def permissions(user=Depends(principal)) -> PermissionCatalog:
        return PermissionCatalog.model_validate({
            'permissions': sorted(user.effective_permissions), 'catalog': catalog(),
            'builtin_roles': {name: sorted(values) for name, values in BUILTIN_PERMISSIONS.items()}})

    @router.get('/api/admin/roles', operation_id='listGovernanceRoles')
    async def role_list(user=Depends(principal)) -> RolesAdmin:
        user.require('roles.manage')
        return RolesAdmin.model_validate(await asyncio.to_thread(product.roles.enterprise.listing, governed(user)))

    @router.post('/api/admin/roles', status_code=201, operation_id='createGovernanceRole')
    async def role_create(body: RoleCreate, user=Depends(principal)) -> GovernanceRole:
        return GovernanceRole.model_validate(await asyncio.to_thread(product.roles.enterprise.create, body, governed(user)))

    @router.put('/api/admin/roles/{identity}', operation_id='updateGovernanceRole')
    async def role_update(identity: str, body: RoleUpdate, user=Depends(principal)) -> GovernanceRole:
        return GovernanceRole.model_validate(
            await asyncio.to_thread(product.roles.enterprise.update, identity, body, governed(user)))

    @router.delete('/api/admin/roles/{identity}', operation_id='archiveGovernanceRole')
    async def role_archive(identity: str, revision: int = Query(ge=1), user=Depends(principal)) -> GovernanceRole:
        return GovernanceRole.model_validate(
            await asyncio.to_thread(product.roles.enterprise.archive, identity, revision, governed(user)))

    @router.put('/api/admin/role-assignments', operation_id='assignGovernanceRole')
    async def assignment(body: RoleAssignment, user=Depends(principal)) -> GovernanceRoleAssignment:
        return GovernanceRoleAssignment.model_validate(
            await asyncio.to_thread(product.roles.enterprise.assign, body, governed(user)))

    @router.put('/api/admin/group-roles/{identity}', operation_id='updateGovernanceGroupRole')
    async def group_role(identity: str, body: GroupRoleChange, user=Depends(principal)) -> GovernanceGroupRole:
        return GovernanceGroupRole.model_validate(
            await asyncio.to_thread(product.roles.enterprise.set_group_role, identity, body, governed(user)))

    @router.get('/api/admin/scim', operation_id='getScimAdmin')
    async def directory(cursor: str | None = None, limit: int = Query(50, ge=1, le=100),
                        user=Depends(principal)) -> ScimAdmin:
        return ScimAdmin.model_validate(await asyncio.to_thread(product.scim.directory, cursor, limit, governed(user)))

    @router.post('/api/admin/scim/tokens', status_code=201, operation_id='createScimToken')
    async def token_create(body: TokenCreate, response: Response, user=Depends(principal)) -> CreatedScimToken:
        response.headers['Cache-Control'] = 'no-store'
        record, token = await asyncio.to_thread(product.scim.create_token, body.label, governed(user))
        return CreatedScimToken.model_validate({**record, 'token': token})

    @router.delete('/api/admin/scim/tokens/{identity}', operation_id='revokeScimToken')
    async def token_revoke(identity: str, user=Depends(principal)) -> ScimToken:
        return ScimToken.model_validate(await asyncio.to_thread(product.scim.revoke_token, identity, governed(user)))

    @router.get('/api/security-profiles', operation_id='listSecurityProfileOptions')
    async def profiles(user=Depends(principal)) -> SessionProfileCatalog:
        user.require('security.manage')
        return SessionProfileCatalog.model_validate(await asyncio.to_thread(product.profiles.catalog))

    def policy_choices():
        """The policy editor's repositories and models, from canonical metadata only (no provider I/O)."""
        connections = runtime.product_connections
        repositories = connections.connectors.github.repository_options() if connections is not None else []
        return ([{'id': row['id'], 'label': row['full_name']} for row in repositories],
                [{'id': model, 'label': MODEL_CATALOG.get(model, model)} for model in runtime.settings.models])

    async def save_profile(body, user, profile_id='') -> SecurityProfileView:
        def save():
            # Only entries the editor could offer may be added; saved ones stay.
            repositories, models = policy_choices()
            return product.profiles.save(body, governed(user), profile_id=profile_id,
                                         known_repositories=[row['id'] for row in repositories],
                                         known_models=[row['id'] for row in models])
        return SecurityProfileView.model_validate(await asyncio.to_thread(save))

    @router.get('/api/admin/security-profiles', operation_id='listSecurityProfiles')
    async def profiles_admin(user=Depends(principal)) -> SecurityProfilesAdmin:
        user.require('security.manage')
        return SecurityProfilesAdmin.model_validate(
            await asyncio.to_thread(lambda: product.profiles.admin_listing(*policy_choices())))

    @router.post('/api/admin/security-profiles', status_code=201, operation_id='createSecurityProfile')
    async def profile_create(body: SaveProfile, user=Depends(principal)) -> SecurityProfileView:
        return await save_profile(body, user)

    @router.put('/api/admin/security-profiles/defaults', operation_id='updateSecurityProfileDefaults')
    async def defaults(body: ProfileDefaults, user=Depends(principal)) -> SecurityProfileDefaults:
        return SecurityProfileDefaults.model_validate(
            await asyncio.to_thread(product.profiles.save_defaults, body, governed(user)))

    @router.put('/api/admin/security-profiles/{identity}', operation_id='updateSecurityProfile')
    async def profile_update(identity: str, body: SaveProfile, user=Depends(principal)) -> SecurityProfileView:
        return await save_profile(body, user, profile_id=identity)

    @router.delete('/api/admin/security-profiles/{identity}', operation_id='disableSecurityProfile')
    async def profile_disable(identity: str, revision: int = Query(ge=1),
                              user=Depends(principal)) -> SecurityProfileView:
        return SecurityProfileView.model_validate(
            await asyncio.to_thread(product.profiles.disable, identity, revision, governed(user)))

    @router.get('/api/sessions/{identity}/security-policy', operation_id='getSessionSecurityPolicy')
    async def session_policy(identity: str, user=Depends(principal)) -> SessionSecurityPolicy:
        user.require('sessions.read')
        async with runtime.database.sessions() as db:
            native = await product.identity.read_native_user(db, user)
            if native is None:
                raise HTTPException(404, 'Session not found.')
            await runtime.database.allowed_session(db, identity, native)
            policy = await runtime.database.governance.policy(db, identity)
            return SessionSecurityPolicy.model_validate({'policy': policy.model_dump(mode='json')})

    async def spend_view(user) -> SpendLimitsAdmin:
        """The limit listing; usage totals only for a caller holding spend.read."""
        data = await asyncio.to_thread(product.spend_limits.listing)
        permitted = 'spend.read' in user.effective_permissions
        usage, organization, amounts = None, None, {}
        if permitted:
            from sqlalchemy import column, select, table

            from .inference_usage import InferenceUsage
            from .product_governance import SpendLedger
            ledger = SpendLedger(runtime.database)
            month = InferenceUsage.created_at >= ledger.period_start
            people = table('users', column('id'), column('email'), schema=product.identity.schema or None)
            async with runtime.database.sessions() as db:
                total, awaiting, in_flight, unresolved = (await db.execute(select(
                    ledger.spent, ledger.awaiting, ledger.in_flight, ledger.unresolved).where(month))).one()
                users = await db.execute(select(people.c.email, ledger.spent, ledger.awaiting)
                                         .join_from(InferenceUsage, people, people.c.id == InferenceUsage.actor_id)
                                         .where(month).group_by(people.c.email))
                # A scope awaiting a cost has no usage (None), exactly as admission sees it.
                amounts = {email: None if blocked else float(spent) for email, spent, blocked in users}
            usage = {'organization_month_usd': float(total), 'period_start': ledger.period_start,
                     'unknown_requests': awaiting, 'in_flight_requests': in_flight,
                     'unresolved_requests': unresolved}
            organization = None if awaiting else usage['organization_month_usd']
        for row in data['limits']:
            row['used_usd'] = None if not permitted else (
                organization if row['kind'] == 'organization'
                else amounts.get(row['subject'], 0) if row['kind'] == 'user' else None)
        return SpendLimitsAdmin.model_validate({**data, 'usage': usage,
                                                'can_manage': 'spend.manage' in user.effective_permissions})

    @router.get('/api/admin/spend-limits', operation_id='getSpendLimits')
    async def spend(user=Depends(principal)) -> SpendLimitsAdmin:
        # A limit manager needs the current revisions; spend_view withholds usage.
        if 'spend.manage' not in user.effective_permissions:
            user.require('spend.read')
        return await spend_view(user)

    @router.put('/api/admin/spend-limits', operation_id='updateSpendLimits')
    async def spend_save(body: SpendLimitChanges, user=Depends(principal)) -> SpendLimitsAdmin:
        await asyncio.to_thread(product.spend_limits.save, body, governed(user))
        return await spend_view(user)

    @router.delete('/api/admin/spend-limits/{identity:path}', operation_id='deleteSpendLimit')
    async def spend_delete(identity: str, revision: int = Query(ge=1), user=Depends(principal)) -> SpendLimitsAdmin:
        await asyncio.to_thread(product.spend_limits.delete, identity, revision, governed(user))
        return await spend_view(user)

    def filters(action, actor_email, resource_type, after, before):
        return parse_filters(action=action, actor=actor_email, resource_type=resource_type,
                             after=after, before=before)

    @router.get('/api/admin/governance/audit', operation_id='listGovernanceAudit')
    async def audit(cursor: str | None = None, limit: int = Query(50, ge=1, le=100),
                    action: str | None = None, actor: str | None = None, resource_type: str | None = None,
                    after: str | None = None, before: str | None = None, user=Depends(principal)) -> AuditPage:
        user.require('audit.read')
        return AuditPage.model_validate(await asyncio.to_thread(
            product.audit.listing, filters(action, actor, resource_type, after, before), cursor, limit))

    @router.get('/api/admin/governance/audit/export', operation_id='exportGovernanceAudit')
    async def audit_export(format: Literal['csv', 'ndjson'] = 'csv', action: str | None = None,
                           actor: str | None = None, resource_type: str | None = None,
                           after: str | None = None, before: str | None = None, user=Depends(principal)):
        user.require('audit.read')
        iterator = await asyncio.to_thread(product.audit.export, filters(action, actor, resource_type, after, before),
                                           format)

        async def content():
            sentinel = object()
            while True:
                current = await product.identity.require_current(user.grant)
                current.require('audit.read')
                chunk = await asyncio.to_thread(next, iterator, sentinel)
                if chunk is sentinel:
                    break
                if not isinstance(chunk, (str, bytes)):
                    raise TypeError('Audit exports must contain text or bytes.')
                yield chunk
        return StreamingResponse(content(), media_type='text/csv' if format == 'csv' else 'application/x-ndjson',
                                 headers={'Content-Disposition': f'attachment; filename="governance.{format}"',
                                          'Cache-Control': 'no-store'})

    return router
