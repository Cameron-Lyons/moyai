"""Native governance boundaries on disposable PostgreSQL; no external provider calls."""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx2
import pytest
import pytest_asyncio
import test_product_authority as authority
import test_product_automations as automation_fixtures
import test_product_inference as inference_fixtures
import test_product_skill_tools as skill_fixtures
from app.security_profiles import ProfilePolicy, SecurityProfiles, dump_policy
from fastapi import HTTPException
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from test_inference_usage import WireStream, payload
from test_product_identity import google_cookie, request
from test_product_inference import perform, requests

from moyai.contracts import NewSession
from moyai.inference_usage import InferenceUsage
from moyai.models import Session
from moyai.product_governance import ProductGovernance
from moyai.product_governance_models import ProductSessionPolicy
from moyai.product_inference import ProductInferenceRequest
from moyai.product_schema import (
    AUTOMATION_CHAT_SCHEMA_VERSION,
    GOVERNANCE_SCHEMA_VERSION,
    migrate_product_schema,
    verify_product_schema,
)

pytestmark = pytest.mark.skipif(not os.getenv('MOYAI_TEST_POSTGRES'), reason='Disposable local PostgreSQL required.')
product_database = authority.product_database
admitted_product = authority.admitted_product
automations = automation_fixtures.automations
skills = skill_fixtures.skills
inference = inference_fixtures.inference


def attach(product):
    resources = SimpleNamespace(identity=product.adapter, profiles=SecurityProfiles(SimpleNamespace(schema_updates=False)))
    governance = ProductGovernance(resources, product.database)
    product.database.governance = governance
    return governance


@pytest_asyncio.fixture
async def governed(admitted_product):
    attach(admitted_product)
    return admitted_product


async def source_write(product, sql, **values):
    async with product.source.begin() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(726941, 'moyai'::regnamespace::oid::int)"))
        await db.execute(text(sql), values)


async def profile(product, policy, *, identity=None, revision=1):
    identity = identity or uuid4().hex
    async with product.source.begin() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(726941, 'moyai'::regnamespace::oid::int)"))
        await db.execute(text('''INSERT INTO moyai.security_profiles VALUES(:id,'Test policy',:rev,1,:policy,'owner','now')
            ON CONFLICT(id) DO UPDATE SET revision=:rev,policy=:policy'''),
            {'id': identity, 'rev': revision, 'policy': dump_policy(ProfilePolicy.model_validate(policy))})
        await db.execute(text("INSERT INTO moyai.security_profile_revisions VALUES(:id,:rev,:policy,'owner','now')"),
                         {'id': identity, 'rev': revision, 'policy': dump_policy(ProfilePolicy.model_validate(policy))})
    return identity


async def defaults(product, selected='', mandatory=''):
    await source_write(product, '''INSERT INTO moyai.security_profile_defaults VALUES(1,1,:selected,:mandatory,'owner','now')
        ON CONFLICT(id) DO UPDATE SET revision=security_profile_defaults.revision+1,
        default_profile_id=:selected,mandatory_profile_id=:mandatory''', selected=selected, mandatory=mandatory)


async def member_role(product, permissions):
    await source_write(product, "INSERT INTO moyai.user_roles VALUES('admin@example.test','member',1,'owner','now')")
    await source_write(product, "INSERT INTO moyai.enterprise_roles VALUES('restricted','Restricted','',:permissions,1,0,'owner','now','now')",
                       permissions=json.dumps(permissions))
    await source_write(product, "INSERT INTO moyai.enterprise_role_assignments VALUES('admin@example.test','restricted',1,'owner','now')")
    principal = await product.adapter.current(product.user_id)
    async with product.database.sessions.begin() as db:
        product.actor = await product.adapter.project_native_user(db, principal)
    product.principal = principal
    return principal


async def test_binding_pins_revision_inherits_parent_and_intersects_live_mandatory(governed):
    product = governed
    selected = await profile(product, {'tools': ['read_file', 'shell'], 'git_access': 'read'})
    await defaults(product, selected)
    parent = await product.database.create_session(product.actor, NewSession())
    await profile(product, {'tools': ['write_file'], 'git_access': 'write'}, identity=selected, revision=2)
    await defaults(product)  # No unrelated default may replace a parent's snapshot.
    child = await product.database.create_session(product.actor, NewSession(), inherited_from=parent.id)
    async with product.database.sessions() as db:
        bound = await db.get(ProductSessionPolicy, child.id)
        assert (bound.profile_id, bound.profile_revision, bound.inherited_from) == (selected, 1, parent.id)
        assert bound.family_root == (await db.get(ProductSessionPolicy, parent.id)).family_root == parent.id
        assert (await product.database.governance.policy(db, child.id)).tools == ('read_file', 'shell')
    mandatory = await profile(product, {'tools': ['read_file'], 'git_access': 'none'})
    await defaults(product, mandatory=mandatory)
    async with product.database.sessions() as db:
        effective = await product.database.governance.policy(db, child.id)
        assert effective.tools == ('read_file',) and effective.git_access == 'none'
    with pytest.raises(DBAPIError, match='immutable'):
        async with product.database.sessions.begin() as db:
            (await db.get(ProductSessionPolicy, child.id)).policy = '{}'
    with pytest.raises(DBAPIError, match='immutable'):
        async with product.database.sessions.begin() as db:
            await db.delete(await db.get(ProductSessionPolicy, child.id))


async def test_default_binding_requires_no_management_but_explicit_selection_does(governed):
    product = governed
    selected = await profile(product, {'git_access': 'read'})
    await defaults(product, selected)
    await member_role(product, ['sessions.create', 'sessions.read'])
    implicit = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions() as db:
        assert (await db.get(ProductSessionPolicy, implicit.id)).profile_id == selected
    with pytest.raises(HTTPException) as denied:
        await product.database.create_session(product.actor, NewSession(security_profile_id=selected))
    assert denied.value.status_code == 403
    # Scheduler selection is server-authored after workflow configuration checks.
    trusted = await product.database.create_session(product.actor, NewSession(security_profile_id=selected), trusted_profile=True)
    assert trusted.id != implicit.id


@pytest.mark.parametrize(('enforcement', 'provider', 'refusal'), [
    ('off', 'modal', 'This deployment cannot enforce'),
    ('modal', 'modal', None),
    ('modal', 'lambda', 'Lambda computers cannot enforce'),
])
async def test_network_policy_refused_atomically_before_native_session_exists(governed, monkeypatch, enforcement,
                                                                            provider, refusal):
    settings = governed.database.settings
    monkeypatch.setattr(settings, 'network_policy_enforcement', enforcement)
    monkeypatch.setattr(settings, 'sandbox_provider', provider)
    selected = await profile(governed, {'network_domains': ['example.test']})
    await defaults(governed, selected)
    if refusal is None:
        session = await governed.database.create_session(governed.actor, NewSession())
        plan = await governed.database.governance.network_plan(session.id)
        assert (plan.domains, plan.session_id) == (('example.test',), session.id)
        return
    with pytest.raises(HTTPException, match=refusal) as denied:
        await governed.database.create_session(governed.actor, NewSession())
    assert denied.value.status_code == 409
    async with governed.database.sessions() as db:
        assert not list(await db.scalars(select(Session.id)))
        assert not list(await db.scalars(select(ProductSessionPolicy.session_id)))


async def test_restricted_sessions_run_on_modal_and_stop_on_an_existing_lambda_computer(governed, monkeypatch):
    """A session's computer keeps its provider, so switching the default to Modal cannot admit a Lambda computer."""
    product, governance = governed, governed.database.governance
    monkeypatch.setattr(product.database.settings, 'network_policy_enforcement', 'modal')
    await defaults(product, await profile(product, {'network_domains': ['pypi.org']}))
    _, _, prepared = await authority.active_turn(product)
    scope = prepared.scope
    await governance.check_tool(scope, 'read_file', read_only=True)
    await governance.check_model(scope, model=scope.model)
    await product.database.authorize_scope(scope)
    for provider, admitted in (('modal', True), ('lambda', False)):
        async with product.database.sessions.begin() as db:
            (await db.get(Session, scope.session_id)).workspace = json.dumps({'provider': provider, 'id': 'computer'})
        for check in (lambda: governance.check_tool(scope, 'read_file', read_only=True),
                      lambda: governance.check_model(scope, model=scope.model),
                      lambda: product.database.authorize_scope(scope)):
            if admitted:
                await check()
            else:
                with pytest.raises(HTTPException, match='Lambda computers cannot enforce'):
                    await check()


async def test_mandatory_narrowing_changes_the_plan_and_refuses_the_running_computer(governed, monkeypatch):
    from unittest.mock import AsyncMock

    from moyai.modal_network import NETWORK_TAG, NetworkPolicyMismatch, modal_kwargs, require_compatible
    product, governance = governed, governed.database.governance
    monkeypatch.setattr(product.database.settings, 'network_policy_enforcement', 'modal')
    await defaults(product, await profile(product, {'network_domains': ['pypi.org', '*.example.test']}))
    _, _, prepared = await authority.active_turn(product)
    created = await governance.network_plan(prepared.scope.session_id)
    computer = SimpleNamespace(object_id='sb-' + uuid4().hex, get_tags=SimpleNamespace(
        aio=AsyncMock(return_value=modal_kwargs(created)['tags'])))
    await require_compatible(created, computer)
    await defaults(product, mandatory=await profile(product, {'network_domains': ['pypi.org']}))
    narrowed = await governance.network_plan(prepared.scope.session_id)
    assert narrowed.domains == ('pypi.org',) and narrowed.tag != created.tag
    with pytest.raises(NetworkPolicyMismatch):
        await require_compatible(narrowed, computer)
    # Loosening needs no action: the computer is within an unrestricted plan.
    await defaults(product, mandatory='')
    await defaults(product)
    assert computer.get_tags.aio.await_count == 1 and NETWORK_TAG in computer.get_tags.aio.return_value


async def test_tools_filtered_and_rechecked_for_policy_and_live_role(governed):
    product = governed
    selected = await profile(product, {'tools': ['read_file', 'shell', 'github_create_pull_request'],
                                       'connected_apps': ['github'], 'git_access': 'read'})
    await defaults(product, selected)
    _, _, prepared = await authority.active_turn(product)
    governance, scope = product.database.governance, prepared.scope
    allowed = await governance.tools(scope, [('read_file', True), ('shell', False), ('write_file', False),
                                              ('github_aaaaaaaa_create_pull_request', False)])
    assert allowed == ['read_file', 'shell']
    await governance.check_tool(scope, 'read_file', read_only=True)
    # Grant-prefixed and shared repository (`github_<operation>`) names are both GitHub writes.
    for name in ('write_file', 'github_aaaaaaaa_create_pull_request', 'open_pull_request',
                 'github_create_pull_request', 'github_publish_branch', 'github_submit_review'):
        with pytest.raises(HTTPException):
            await governance.check_tool(scope, name, read_only=False)
    await member_role(product, ['sessions.read'])
    with pytest.raises(HTTPException):
        await governance.check_tool(scope, 'read_file', read_only=True)
    with pytest.raises(HTTPException):
        await product.database.create_session(product.actor, NewSession())


async def test_policy_editor_operation_names_allowlist_shared_repository_tools(governed):
    product = governed
    selected = await profile(product, {'tools': ['create_pull_request', 'checkout'], 'connected_apps': ['github']})
    await defaults(product, selected)
    _, _, prepared = await authority.active_turn(product)
    governance, scope = product.database.governance, prepared.scope
    tools = [('github_create_pull_request', False), ('github_checkout', True), ('github_publish_branch', False)]
    assert await governance.tools(scope, tools) == ['github_create_pull_request', 'github_checkout']
    await member_role(product, ['sessions.create', 'sessions.read', 'connections.read'])
    _, _, prepared = await authority.active_turn(product)
    # Without connections.write, the shared repository writes are refused too.
    assert await governance.tools(prepared.scope, tools) == ['github_checkout']


async def test_scim_reactivation_never_revives_an_earlier_native_grant(governed):
    product, old = governed, governed.principal.grant
    await source_write(product, '''INSERT INTO moyai.scim_users VALUES('directory-person','','admin@example.test','{}',0,'','now','now',1,1)''')
    with pytest.raises(HTTPException) as denied:
        await product.adapter.require_current(old)
    assert denied.value.status_code == 401
    await source_write(product, "UPDATE moyai.scim_users SET active=1,revision=2 WHERE id='directory-person'")
    fresh = await product.adapter.current(product.user_id)
    assert fresh.grant != old
    with pytest.raises(HTTPException):
        await product.adapter.require_current(old)
    assert await product.adapter.require_current(fresh.grant) == fresh


async def test_http_permissions_are_enforced_independently_of_settings_visibility(governed):
    product = governed
    await member_role(product, ['workspace.read', 'sessions.read'])
    cookie, _ = google_cookie(product.adapter, sub=product.subject)
    incoming = request(cookie)
    incoming.scope['path'] = '/api/admin/security-profiles'
    with pytest.raises(HTTPException) as denied:
        await product.adapter.authenticate(incoming)
    assert denied.value.status_code == 403
    incoming.scope['path'] = '/api/sessions'
    assert (await product.adapter.authenticate(incoming)).effective_permissions == {'workspace.read', 'sessions.read'}


async def test_workflow_selection_and_session_ceiling_are_checked(governed):
    from moyai.product_automations import AutomationDefinition
    product = governed
    restricted = await profile(product, {'tools': ['read_file'], 'connected_apps': [], 'git_access': 'none'})
    await defaults(product, restricted)
    _, _, prepared = await authority.active_turn(product)
    definition = AutomationDefinition(name='Governed', prompt='Work', security_profile_id=restricted)
    governance = product.database.governance
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        await governance.workflow(db, principal, definition, scope=prepared.scope, model='test')
    await defaults(product)  # A source session cannot create an unrestricted workflow.
    definition.security_profile_id = ''
    with pytest.raises(HTTPException, match='cannot exceed'):
        async with product.database.sessions.begin() as db:
            await governance.workflow(db, product.principal, definition, scope=prepared.scope, model='test')
    principal = await member_role(product, ['sessions.create', 'sessions.read', 'automations.manage'])
    definition.security_profile_id = restricted
    async with product.database.sessions.begin() as db:
        await governance.workflow(db, principal, definition, previous=restricted, model='test')
    with pytest.raises(HTTPException):
        async with product.database.sessions.begin() as db:
            await governance.workflow(db, principal, definition, model='test')


@pytest.mark.parametrize(('provider', 'admitted'), [('modal', True), ('lambda', False)])
async def test_workflow_network_policies_follow_the_default_provider(governed, monkeypatch, provider, admitted):
    from moyai.product_automations import AutomationDefinition
    product, governance = governed, governed.database.governance
    monkeypatch.setattr(product.database.settings, 'network_policy_enforcement', 'modal')
    monkeypatch.setattr(product.database.settings, 'sandbox_provider', provider)
    offline = await profile(product, {'network_domains': []})
    definition = AutomationDefinition(name='Offline', prompt='Work', security_profile_id=offline)
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        if admitted:
            await governance.workflow(db, principal, definition, model='test')
        else:
            with pytest.raises(HTTPException, match='Lambda computers cannot enforce'):
                await governance.workflow(db, principal, definition, model='test')


@pytest.mark.parametrize('kind', ['organization', 'user-default', 'session-default', 'user'])
async def test_spend_limits_block_actual_paid_dispatch_at_each_scope(inference, kind):
    ctx = inference
    attach(ctx.product)
    identity = 'user:admin@example.test' if kind == 'user' else kind
    await source_write(ctx.product, 'INSERT INTO moyai.spend_limits VALUES(:id,:kind,:subject,0.20,1,\'owner\',\'now\')',
                       id=identity, kind=kind, subject='admin@example.test' if kind == 'user' else '')
    await perform(ctx, cost='0.25')  # Soft threshold: this admitted request can cross it.
    with pytest.raises(HTTPException, match='spend limit'):
        await perform(ctx, logical='second')
    assert len(ctx.calls) == len(await requests(ctx)) == 1


async def test_zero_budget_and_unpriced_cost_block_before_provider_call(inference):
    ctx = inference
    attach(ctx.product)
    await source_write(ctx.product, "INSERT INTO moyai.spend_limits VALUES('organization','organization','',0,1,'owner','now')")
    with pytest.raises(HTTPException, match='spend limit'):
        await perform(ctx)
    assert not ctx.calls and not await requests(ctx)
    await source_write(ctx.product, "UPDATE moyai.spend_limits SET limit_usd=10 WHERE id='organization'")
    entered, release = asyncio.Event(), asyncio.Event()

    async def provider(request):
        import httpx2
        entered.set()
        await release.wait()
        return httpx2.Response(200, json={'usage': {}, 'id': 'synthetic'})

    first = asyncio.create_task(perform(ctx, logical='first', handler=provider))
    await asyncio.wait_for(entered.wait(), 5)
    try:
        # An in-flight request neither counts nor serializes other budgeted work.
        await perform(ctx, logical='concurrent')
    finally:
        release.set()
        await first
    assert len(ctx.calls) == 2
    # A finished request without a reported cost makes the limit fail closed.
    await perform(ctx, logical='unpriced', cost=None)
    with pytest.raises(HTTPException, match='spend limit'):
        await perform(ctx, logical='after')
    assert len(ctx.calls) == 3


async def test_governance_schema_adds_receipt_without_changing_v23(product_database):
    product = product_database
    await migrate_product_schema(product.source, schema=product.schema, source_schema='moyai',
                                 version=AUTOMATION_CHAT_SCHEMA_VERSION)
    async with product.source.connect() as db:
        before = (await db.execute(text(f'SELECT * FROM "{product.schema}".moyai_app_schema_versions'))).all()
    await migrate_product_schema(product.source, schema=product.schema, source_schema='moyai')
    await verify_product_schema(product.source, schema=product.schema)
    async with product.source.connect() as db:
        after = (await db.execute(text(f'SELECT * FROM "{product.schema}".moyai_app_schema_versions'))).all()
    assert [row for row in after if row[0] != GOVERNANCE_SCHEMA_VERSION] == before


async def test_actual_tool_activity_retry_rechecks_policy_before_provider(governed, monkeypatch):
    from temporalio.exceptions import ApplicationError
    from temporalio.worker import ExecuteActivityInput

    from moyai.execution import AuthorizedActivity
    product = governed
    _, _, prepared = await authority.active_turn(product)
    info = SimpleNamespace(activity_type='agent__moyai__toolset__fixture__call_tool')
    monkeypatch.setattr('moyai.execution.activity.info', lambda: info)
    calls = []
    class Next:
        async def execute_activity(self, value):
            calls.append(value)
            return 'read'
    wire = SimpleNamespace(name='read_file', serialized_run_context={}, tool_def=None)
    value = ExecuteActivityInput(fn=lambda: None, args=[wire, prepared.scope], executor=None, headers={})
    interceptor = AuthorizedActivity(Next(), product.database)
    assert await interceptor.execute_activity(value) == 'read'
    mandatory = await profile(product, {'tools': []})
    await defaults(product, mandatory=mandatory)
    with pytest.raises(ApplicationError) as denied:
        await interceptor.execute_activity(value)
    assert denied.value.type == 'MoyaiPermissionDenied' and denied.value.non_retryable
    assert len(calls) == 1


async def test_child_spend_is_charged_to_the_parent_session_limit(inference):
    ctx = inference
    attach(ctx.product)
    child = await ctx.product.database.create_session(ctx.product.actor, NewSession(), inherited_from=ctx.session.id)
    await source_write(ctx.product, "INSERT INTO moyai.spend_limits VALUES('session-default','session-default','',0.2,1,'owner','now')")
    await perform(ctx, cost='0.25')
    grandchild = await ctx.product.database.create_session(ctx.product.actor, NewSession(), inherited_from=child.id)
    async with ctx.product.database.sessions() as db:
        # The parent predates its family's bindings, so it heads the family.
        assert (await db.get(ProductSessionPolicy, grandchild.id)).family_root == ctx.session.id
    for member in (child, grandchild):
        with pytest.raises(HTTPException, match='spend limit'):
            await ctx.product.database.governance.check_model(replace(ctx.scope, session_id=member.id), model='test')


async def session_limit(product):
    await source_write(product, "INSERT INTO moyai.spend_limits VALUES('session-default','session-default','',10,1,'owner','now')")


@pytest.mark.parametrize('outcome', ['parked', 'expired', 'missing', 'disabled', 'rotated'])
async def test_unpriced_request_blocks_only_while_recovery_can_settle_it(inference, outcome):
    ctx = inference
    attach(ctx.product)
    await session_limit(ctx.product)
    await perform(ctx, logical='unpriced', cost=None)
    with pytest.raises(HTTPException, match='spend limit'):
        await perform(ctx, logical='blocked')
    headers = None
    async with ctx.product.database.sessions.begin() as db:
        if outcome == 'parked':
            await db.execute(update(ProductInferenceRequest).values(next_attempt_at=None, recovery_error='unverified_zero'))
        elif outcome == 'expired':
            old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
            await db.execute(update(InferenceUsage).values(created_at=old))
        elif outcome == 'missing':
            # LiteLLM never logged it: recovery keeps retrying, but it blocks only for the first hour.
            await db.execute(update(ProductInferenceRequest).values(recovery_error='not_found'))
    if outcome == 'missing':
        with pytest.raises(HTTPException, match='spend limit'):
            await perform(ctx, logical='still-blocked')
        async with ctx.product.database.sessions.begin() as db:
            old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
            await db.execute(update(InferenceUsage).values(created_at=old))
    if outcome == 'disabled':
        ctx.service.settings.litellm_spend_recovery_enabled = False
    elif outcome == 'rotated':
        ctx.service.settings.litellm_api_key = 'rotated-inference-key'
        headers = {'authorization': 'Bearer rotated-inference-key'}
    await perform(ctx, logical='admitted', headers=headers)
    assert len(ctx.calls) == 2


async def test_gateway_errors_and_duplicate_receipts_never_block_a_limit(inference):
    ctx = inference
    attach(ctx.product)
    await session_limit(ctx.product)

    async def rejected(_):
        return httpx2.Response(429, stream=WireStream(b'<html>Busy</html>'), headers={'content-type': 'text/html'})

    async def same_receipt(_):
        return httpx2.Response(200, stream=WireStream(json.dumps(payload(cost='0.125')).encode()),
                               headers={'content-type': 'application/json', 'x-litellm-call-id': 'same-receipt'})
    assert (await perform(ctx, logical='rejected', handler=rejected)).status_code == 429
    await perform(ctx, logical='first', handler=same_receipt)
    await perform(ctx, logical='second', handler=same_receipt)
    async with ctx.product.database.sessions() as db:
        errors = list(await db.scalars(select(InferenceUsage.coverage_error).where(InferenceUsage.cost_usd.is_(None))))
    assert sorted(errors) == ['duplicate_provider_receipt', 'gateway_error']
    await perform(ctx, logical='admitted')
    assert len(ctx.calls) == 4


async def test_pending_request_counts_once_it_outlives_the_model_timeout(inference, monkeypatch):
    ctx = inference
    attach(ctx.product)
    await session_limit(ctx.product)

    async def unavailable(_):
        raise RuntimeError('synthetic final accounting outage')
    monkeypatch.setattr(ctx.service, 'observe', unavailable)
    await perform(ctx, logical='lost')  # Its final status and cost are never written.
    monkeypatch.undo()
    await perform(ctx, logical='in-flight')  # Still within the model timeout.
    started = datetime.now(UTC) - timedelta(seconds=ctx.product.database.settings.model_timeout_seconds + 120)
    async with ctx.product.database.sessions.begin() as db:
        await db.execute(update(InferenceUsage).where(InferenceUsage.status == 'pending')
                         .values(created_at=started.isoformat()))
    with pytest.raises(HTTPException, match='spend limit'):
        await perform(ctx, logical='after')
    assert len(ctx.calls) == 2


async def test_spend_page_reports_usage_as_admission_counts_it(inference):
    ctx = inference
    attach(ctx.product)
    await perform(ctx, logical='priced', cost='0.25')
    await perform(ctx, logical='parked', cost=None)
    async with ctx.product.database.sessions.begin() as db:
        await db.execute(update(ProductInferenceRequest).where(ProductInferenceRequest.cost_usd.is_(None))
                         .values(next_attempt_at=None, recovery_error='unverified_zero'))
    entered, release = asyncio.Event(), asyncio.Event()

    async def running(_):
        entered.set()
        await release.wait()
        return httpx2.Response(200, stream=WireStream(json.dumps(payload()).encode()),
                               headers={'content-type': 'application/json'})
    person = {**SPEND_ROW, 'id': 'user:admin@example.test', 'kind': 'user', 'subject': 'admin@example.test'}

    class Listing:
        def listing(self):
            return {'limits': [dict(SPEND_ROW), dict(person)]}
    task = asyncio.create_task(perform(ctx, logical='running', handler=running))
    async with governance_client(ctx.product, spend_limits=Listing()) as client:
        try:
            await asyncio.wait_for(entered.wait(), 5)
            running_body = (await client.get('/api/admin/spend-limits')).json()
        finally:
            release.set()
            await task
        finished_body = (await client.get('/api/admin/spend-limits')).json()
    counts = ('organization_month_usd', 'unknown_requests', 'in_flight_requests', 'unresolved_requests')
    assert tuple(running_body['usage'][key] for key in counts) == (0.25, 0, 1, 1)
    assert [row['used_usd'] for row in running_body['limits']] == [0.25, 0.25]
    # Finished without a cost, it now awaits recovery and blocks both scopes.
    assert tuple(finished_body['usage'][key] for key in counts) == (0.25, 1, 0, 1)
    assert [row['used_usd'] for row in finished_body['limits']] == [None, None]


async def test_workflow_update_checks_the_submitted_definition_inside_the_writer(automations):
    from test_product_automations import definition

    from moyai.product_automations import Save
    ctx = automations
    attach(ctx.product)
    selected = await profile(ctx.product, {'connected_apps': [], 'git_access': 'none'})
    saved = await ctx.service.mutate(ctx.grant, 'create', None, Save(
        definition=definition(security_profile_id=selected), revision=0, request_key='governed-create'))
    principal = await member_role(ctx.product, ['sessions.create', 'sessions.read', 'automations.manage'])
    for changes in ({'plugins': ['github']}, {'security_profile_id': ''}):
        body = Save(definition=definition(security_profile_id=selected).model_copy(update=changes),
                    revision=saved['revision'], request_key=uuid4().hex)
        with pytest.raises(HTTPException) as denied:
            await ctx.service.mutate(principal.grant, 'update', saved['id'], body)
        assert denied.value.status_code == 403
    async with ctx.product.source.connect() as db:
        row = (await db.execute(text('SELECT revision,definition FROM moyai.automations WHERE id=:id'),
                                {'id': saved['id']})).mappings().one()
    assert row['revision'] == saved['revision']
    assert json.loads(row['definition'])['plugins'] == []


def test_empty_profile_keeps_existing_automation_authority_digest():
    from test_product_automations import definition

    from moyai.product_automations import _digest, definition_digest
    # Absent optional fields (no profile selection, no chat destination) are
    # omitted, so enabled definitions written before either keep their digest.
    value = definition().model_dump(mode='json', exclude={'security_profile_id', 'session_id'})
    assert definition_digest(definition()) == _digest(value)
    assert definition_digest(definition(security_profile_id='a' * 32)) != _digest(value)


async def test_custom_publisher_uses_native_skill_writer_without_builtin_admin(skills):
    from test_product_skill_tools import call, content

    from moyai.product_skill_tools import CreateSkill
    ctx = skills
    attach(ctx.product)
    principal = await member_role(ctx.product, ['sessions.create', 'sessions.read', 'skills.read', 'skills.manage', 'skills.publish'])
    assert principal.role == 'member'
    _, _, prepared = await authority.active_turn(ctx.product)
    created, _ = await call(ctx, 'skill_create', CreateSkill(**content(), scope='organization'), scope=prepared.scope)
    async with ctx.product.source.connect() as db:
        assert await db.scalar(text('SELECT scope FROM moyai.skills WHERE id=:id'), {'id': created['id']}) == 'organization'


def governance_client(product, **services):
    import httpx
    from fastapi import APIRouter, FastAPI

    from moyai.product_governance_routes import routes
    database = services.pop('database', product.database)
    connections = services.pop('product_connections', None)
    resources = product.database.governance.product
    resources.scim = SimpleNamespace(router=lambda: APIRouter())
    for name, service in services.items():
        setattr(resources, name, service)
    app = FastAPI()
    app.include_router(routes(SimpleNamespace(product=resources, database=database, settings=product.database.settings,
                                              product_connections=connections)))
    cookie, csrf = google_cookie(product.adapter, sub=product.subject)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8787',
                               headers={'origin': 'http://127.0.0.1:8787', 'x-csrf-token': csrf})
    client.cookies.set('workspace_session', cookie)
    return client


SPEND_ROW = {'id': 'organization', 'kind': 'organization', 'subject': '', 'limit_usd': 10.0, 'revision': 1,
             'updated_at': '2026-10-21T00:00:00Z', 'updated_by': 'admin@example.test'}


async def test_spend_management_without_read_permission_does_not_return_usage(governed, monkeypatch):
    product = governed
    await member_role(product, ['spend.manage'])
    class ConfigurationOnly:
        def save(self, body, actor):
            return {'limits': [SPEND_ROW]}
        def delete(self, identity, revision, actor):
            return {'id': identity, 'deleted': True}
        def listing(self):
            return {'limits': [SPEND_ROW]}
    def no_usage():
        pytest.fail('A limit writer without spend.read reached the usage query.')
    async with governance_client(product, spend_limits=ConfigurationOnly(),
                                 database=SimpleNamespace(sessions=no_usage)) as client:
        configuration = {'limits': [{**SPEND_ROW, 'used_usd': None}], 'usage': None, 'can_manage': True}
        response = await client.put('/api/admin/spend-limits', json={'changes': [{'id': 'organization', 'limit_usd': 10.0, 'revision': 0}]})
        assert response.status_code == 200 and response.json() == configuration
        response = await client.delete('/api/admin/spend-limits/user:person@example.test?revision=1')
        assert response.status_code == 200 and response.json() == configuration
        # Exercise the handler's own check; route_permission is tested on its own.
        monkeypatch.setattr('app.permissions.route_permission', lambda request: None)
        response = await client.get('/api/admin/spend-limits')
        assert response.status_code == 200 and response.json() == configuration
        await source_write(product, "UPDATE moyai.enterprise_roles SET permissions='[\"workspace.read\"]' WHERE id='restricted'")
        assert (await client.get('/api/admin/spend-limits')).status_code == 403


async def test_policy_editor_offers_installation_repositories_and_workspace_models(governed, monkeypatch):
    """The editor catalog comes from canonical repository metadata and the enabled models; saves may add only those."""
    from app.security_profiles import policy_catalog
    product, seen = governed, {}
    monkeypatch.setattr(product.database.settings, 'model_catalog', 'openai/gpt-6-astra')
    view = {'id': 'a' * 32, 'name': 'Limited', 'enabled': True, 'revision': 1, 'updated_at': 'now', 'updated_by': 'owner',
            'policy': ProfilePolicy(repositories=[7], models=['openai/gpt-6-astra']).model_dump(mode='json')}
    class Profiles:
        def admin_listing(self, repositories, models):
            return {'profiles': [view], 'catalog': policy_catalog(repositories, models), 'defaults': {
                'default_profile_id': '', 'mandatory_profile_id': '', 'revision': 0, 'updated_at': None, 'updated_by': ''}}
        def save(self, body, actor, *, profile_id='', known_repositories=None, known_models=None):
            seen[profile_id] = (body.policy.model_fields_set >= {'repositories', 'models'}, known_repositories, known_models)
            return view
    class Repositories:
        def repository_options(self):
            return [{'id': 7, 'full_name': 'acme/app'}]
    connections = SimpleNamespace(connectors=SimpleNamespace(github=Repositories()))
    async with governance_client(product, profiles=Profiles(), product_connections=connections) as client:
        listing = (await client.get('/api/admin/security-profiles')).json()
        assert listing['catalog']['network_enforcement'] == 'off'
        monkeypatch.setattr(product.database.settings, 'network_policy_enforcement', 'modal')
        assert (await client.get('/api/admin/security-profiles')).json()['catalog']['network_enforcement'] == 'modal'
        assert listing['catalog']['repositories'] == [{'id': 7, 'label': 'acme/app'}]
        assert listing['catalog']['models'] == [{'id': 'test', 'label': 'test'},
                                                {'id': 'openai/gpt-6-astra', 'label': 'GPT-6 Astra'}]
        assert listing['profiles'][0]['policy']['repositories'] == [7]
        body = {'name': 'Limited', 'policy': {'repositories': [7], 'models': ['openai/gpt-6-astra']}}
        assert (await client.post('/api/admin/security-profiles', json=body)).status_code == 201
        assert (await client.put(f"/api/admin/security-profiles/{'a' * 32}", json={**body, 'revision': 1})).status_code == 200
        for invalid in ({'repositories': [True]}, {'repositories': ['7']}, {'models': ['a b']}):
            response = await client.post('/api/admin/security-profiles', json={'name': 'Invalid', 'policy': invalid})
            assert response.status_code == 422
    assert seen == {key: (True, [7], ['test', 'openai/gpt-6-astra']) for key in ('', 'a' * 32)}


async def test_scim_token_creation_returns_the_one_time_token_in_its_record(governed):
    product = governed
    record = {'id': 'a' * 32, 'label': 'Okta', 'prefix': 'moyai_scim_aaaaaaaa', 'created_at': '2026-10-21T00:00:00Z',
              'created_by': 'admin@example.test', 'last_used_at': None, 'revoked_at': None}
    class Provisioning:
        def router(self):
            from fastapi import APIRouter
            return APIRouter()
        def create_token(self, label, actor):
            return {**record, 'label': label}, 'moyai_scim_secret'
        def revoke_token(self, identity, actor):
            return {**record, 'revoked_at': '2026-10-21T01:00:00Z'}
    async with governance_client(product, scim=Provisioning()) as client:
        created = await client.post('/api/admin/scim/tokens', json={'label': 'Entra'})
        assert created.status_code == 201 and created.headers['cache-control'] == 'no-store'
        assert created.json() == {**record, 'label': 'Entra', 'token': 'moyai_scim_secret'}
        revoked = await client.delete(f"/api/admin/scim/tokens/{record['id']}")
        assert revoked.status_code == 200 and revoked.json()['revoked_at'] == '2026-10-21T01:00:00Z'


async def test_scheduled_chat_destination_cannot_widen_the_workflow_policy(governed):
    product, governance = governed, governed.database.governance
    unrestricted = await product.database.create_session(product.actor, NewSession())
    restricted = await profile(product, {'tools': ['read_file'], 'git_access': 'read'})
    await defaults(product, restricted)
    bound = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions.begin() as db:
        await governance.continuation(db, bound.id, restricted)
        await governance.continuation(db, bound.id)  # The default is the same profile.
    with pytest.raises(HTTPException, match='allows more than'):
        async with product.database.sessions.begin() as db:
            await governance.continuation(db, unrestricted.id, restricted)
    await defaults(product)  # A narrower chat may serve an unrestricted workflow.
    async with product.database.sessions.begin() as db:
        await governance.continuation(db, bound.id)


async def test_delegated_child_binds_the_parent_snapshot_not_a_newer_default(governed, monkeypatch):
    from moyai.delegation import DelegationService
    product = governed
    monkeypatch.setattr(product.database.settings, 'network_policy_enforcement', 'modal')
    selected = await profile(product, {'tools': ['read_file', 'shell'], 'git_access': 'read',
                                       'network_domains': ['pypi.org', '*.example.test']})
    await defaults(product, selected)
    _, _, prepared = await authority.active_turn(product)
    await defaults(product)  # A newer unrestricted default must not reach the child.
    child = await DelegationService(product.database).start(prepared.scope, 'child', 'Work')
    async with product.database.sessions() as db:
        bound = await db.get(ProductSessionPolicy, child['session_id'])
        assert (bound.profile_id, bound.inherited_from) == (selected, prepared.scope.session_id)
        policy = await product.database.governance.policy(db, child['session_id'])
        assert policy.tools == ('read_file', 'shell') and policy.git_access == 'read'
    # The child's computer follows the parent snapshot, narrowed by the live mandatory policy.
    plan = await product.database.governance.network_plan(child['session_id'])
    assert plan.domains == ('*.example.test', 'pypi.org') and plan.session_id == child['session_id']
    await defaults(product, mandatory=await profile(product, {'network_domains': ['api.example.test']}))
    assert (await product.database.governance.network_plan(child['session_id'])).domains == ('api.example.test',)


async def test_audit_feed_and_export_apply_the_requested_window(governed):
    product = governed
    seen = []
    class Recording:
        def listing(self, filters, cursor, limit):
            seen.append(filters)
            return {'entries': [], 'next_cursor': None, 'facets': {'actions': [], 'resource_types': []}}
        def export(self, filters, format):
            seen.append(filters)
            return iter(())
    window = {'after': '2026-10-01T00:00:00Z', 'before': '2026-10-16T00:00:00Z'}
    async with governance_client(product, audit=Recording()) as client:
        assert (await client.get('/api/admin/governance/audit', params=window)).status_code == 200
        assert (await client.get('/api/admin/governance/audit/export', params=window)).status_code == 200
        assert (await client.get('/api/admin/governance/audit/export', params={'format': 'xml'})).status_code == 422
    assert [(f.after.isoformat(), f.before.isoformat()) for f in seen] == [
        ('2026-10-01T00:00:00+00:00', '2026-10-16T00:00:00+00:00')] * 2


@pytest.mark.parametrize('lost', ['permission', 'authority'])
async def test_audit_export_stops_when_permission_is_lost_between_pages(governed, monkeypatch, lost):
    """The export rechecks live audit.read before releasing each page, not just at request time."""
    product, released = governed, []
    class TwoPages:
        def export(self, filters, format):
            for chunk in ('created_at,action\nfirst\n', 'second\n'):
                released.append(chunk)
                yield chunk
    original = product.adapter.require_current
    async def changed_after_first_page(grant):
        principal = await original(grant)
        if released and lost == 'authority':
            raise HTTPException(401, 'Product authority changed; fresh authorization is required.')
        # Otherwise live authority still verifies, but the role no longer grants audit.read.
        return replace(principal, permissions=frozenset()) if released else principal
    monkeypatch.setattr(product.adapter, 'require_current', changed_after_first_page)
    async with governance_client(product, audit=TwoPages()) as client:
        # The 200 status and headers are already sent, so Starlette re-raises
        # the handled HTTPException as a RuntimeError caused by it.
        with pytest.raises(RuntimeError) as raised:
            await client.get('/api/admin/governance/audit/export')
    cause = raised.value.__cause__
    assert isinstance(cause, HTTPException) and cause.status_code == (403 if lost == 'permission' else 401)
    assert released == ['created_at,action\nfirst\n']  # The second page was never pulled from the store.


async def test_no_git_access_refuses_github_grants_and_workflow_plugins(governed):
    from moyai.product_automations import AutomationDefinition
    product, governance = governed, governed.database.governance
    await defaults(product, await profile(product, {'git_access': 'none'}))
    session = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        await governance.admission(db, session, principal, [SimpleNamespace(kind='linear', policy={})])
        await governance.workflow(db, principal, AutomationDefinition(name='Issues', prompt='Work', plugins=['linear']),
                                  model='test')
        with pytest.raises(HTTPException, match='disabled by the session security policy'):
            await governance.admission(db, session, principal, [SimpleNamespace(kind='github', policy={})])
        with pytest.raises(HTTPException, match='connections exceed'):
            await governance.workflow(db, principal, AutomationDefinition(name='Git', prompt='Work', plugins=['github']),
                                      model='test')


async def test_credential_release_and_workspace_preparation_recheck_live_policy(governed):
    """Credential release and workspace preparation refuse what the live role and policy no longer allow."""
    from moyai.product_continuation_models import ProductExecutionContext
    from moyai.product_continuation_workspace import ProductWorkspaceCompatibility, fingerprint
    product, governance = governed, governed.database.governance
    _, _, prepared = await authority.active_turn(product)
    scope, github = prepared.scope, SimpleNamespace(kind='github', policy={})
    repository = {'source_schema': 'moyai', 'repo_url': 'https://github.com/acme/app'}
    async with product.database.sessions.begin() as db:
        db.add(ProductExecutionContext(turn_id=scope.turn_id, actor_id=scope.actor_id,
                                       descriptor=product.database.security.seal(repository),
                                       fingerprint=fingerprint(repository)))
    workspace = ProductWorkspaceCompatibility(SimpleNamespace(
        database=product.database, security=product.database.security, product_identity=product.adapter))
    await governance.connection(scope, github, write=True)
    assert await workspace.turn_context(scope) == repository
    await defaults(product, mandatory=await profile(product, {'git_access': 'read'}))
    with pytest.raises(HTTPException, match='Managed Git access'):
        await governance.connection(scope, github, write=True)
    await governance.connection(scope, github)
    await defaults(product, mandatory=await profile(product, {'connected_apps': ['linear']}))
    with pytest.raises(HTTPException, match='connection is disabled'):
        await governance.connection(scope, github)
    # Each check runs in its own transaction, so it reads the policy just written.
    with pytest.raises(HTTPException, match='repository exceeds'):
        await workspace.turn_context(scope)
    await defaults(product)
    principal = await member_role(product, ['sessions.create', 'sessions.read'])
    scope = replace(scope, product_grant=principal.grant)
    for check in (lambda db: governance.workspace(db, scope, {'environment_build_id': 'build'}),
                  lambda db: governance.workspace(db, scope, repository)):
        with pytest.raises(HTTPException, match='role does not allow'):
            async with product.database.sessions.begin() as db:
                await check(db)
    async with product.database.sessions.begin() as db:
        await governance.workspace(db, scope, {})
    with pytest.raises(HTTPException, match='role does not allow'):
        await governance.connection(scope, github)


async def test_network_mandatory_policy_stops_a_running_session(governed):
    """A mandatory network restriction stops a running session, not only new ones."""
    product, governance = governed, governed.database.governance
    _, _, prepared = await authority.active_turn(product)
    scope = prepared.scope
    await governance.check_tool(scope, 'read_file', read_only=True)
    await governance.check_model(scope, model=scope.model)
    await defaults(product, mandatory=await profile(product, {'network_domains': []}))
    for check in (lambda: governance.check_tool(scope, 'read_file', read_only=True),
                  lambda: governance.check_model(scope, model=scope.model), lambda: product.database.authorize_scope(scope)):
        with pytest.raises(HTTPException, match='cannot enforce'):
            await check()


async def test_tool_catalog_checks_scope_and_policy_in_one_transaction(governed, monkeypatch):
    """Regression: the per-step catalog resolved the principal and policy again in a second transaction."""
    from temporalio.exceptions import ApplicationError

    from moyai.agent import Authority
    product = governed
    await defaults(product, await profile(product, {'tools': ['read_file']}))
    _, _, prepared = await authority.active_turn(product)
    catalog, resolved = Authority(product.database).governance_catalog, []
    original = product.adapter._current
    async def counted(*args, **kwargs):
        resolved.append(1)
        return await original(*args, **kwargs)
    monkeypatch.setattr(product.adapter, '_current', counted)
    assert await catalog(prepared.scope, [('read_file', True), ('shell', False)]) == ['read_file']
    assert len(resolved) == 1
    await defaults(product, mandatory=await profile(product, {'network_domains': []}))
    with pytest.raises(HTTPException, match='cannot enforce'):
        await catalog(prepared.scope, [('read_file', True)])
    # In an activity attempt a refusal keeps the activity interceptor's error type.
    monkeypatch.setattr('moyai.agent.activity.in_activity', lambda: True)
    with pytest.raises(ApplicationError) as denied:
        await catalog(prepared.scope, [('read_file', True)])
    assert denied.value.type == 'MoyaiPermissionDenied' and denied.value.non_retryable


canonical_connections = automation_fixtures.canonical_connections


@pytest.mark.parametrize('permissions', [None, ['sessions.create', 'sessions.read']])
async def test_slack_auto_selection_keeps_only_connections_the_policy_and_role_allow(
        automations, canonical_connections, permissions):
    from sqlalchemy import update

    from moyai.models import Turn
    from moyai.product_slack_conversations import SlackConversation
    from moyai.product_slack_events import SlackEvents, SlackMessage
    ctx = automations
    product = ctx.product
    attach(product)
    for provider in ('linear', 'notion'):
        await automation_fixtures.save_connection(ctx, provider)
    await defaults(product, await profile(product, {'connected_apps': ['linear']}))
    principal = product.principal if permissions is None else await member_role(product, permissions)
    session = await product.database.create_session(product.actor, NewSession(visibility='shared'))
    async with product.database.sessions.begin() as db:
        await db.execute(update(Session).where(Session.id == session.id).values(surface='slack'))
        grants = await canonical_connections.resolve_grants(
            product.actor.id, ['linear', 'notion'], shared_session=True, surface='slack', db=db)
    await automation_fixtures.bind_slack_test_session(product.database, session.id, product.actor)

    async def catalog(actor_id, *, shared_session, surface):
        return [{'id': grant.id, 'kind': grant.kind, 'policy': grant.policy} for grant in grants]

    events = SlackEvents(SimpleNamespace(
        runtime=SimpleNamespace(database=product.database, slack_activity=SimpleNamespace(wake=asyncio.Event())),
        connections=SimpleNamespace(catalog=catalog), delivery_wakeup=asyncio.Event(),
    ))
    origin = {'team_id': 'TTEST0001', 'channel_id': 'DTEST0001', 'thread_ts': '1792255740.000',
              'message_ts': '1792255800.000', 'user_id': 'UTEST0001', 'event_id': 'governed-slack'}
    message = SlackMessage({}, None, origin, 'Work', mentioned=True, direct=True, key='governed-slack', command=None)
    thread = SimpleNamespace(session_id=session.id)
    await events._admit(message, SlackConversation(thread=thread), product.actor, principal, {'authority': 'a' * 64})
    async with product.database.sessions() as db:
        turn = await db.scalar(select(Turn).where(Turn.session_id == session.id))
    # Slack has no account picker: excluded kinds, or every kind without
    # connections.read, are left out instead of refusing the message.
    assert json.loads(turn.connections) == ([grant.id for grant in grants if grant.kind == 'linear']
                                            if permissions is None else [])


@pytest.mark.parametrize('change', ['disabled', 'narrowed'])
async def test_scheduled_governance_refusal_blocks_the_workflow_instead_of_retrying(automations, change):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func

    from moyai.models import Turn
    from moyai.product_automation_models import ProductAutomationBinding as Binding
    from moyai.product_automations import GOVERNANCE_BLOCKED
    ctx = automations
    product = ctx.product
    attach(product)
    selected = await profile(product, {})
    chat = None
    if change == 'narrowed':
        chat = (await product.database.create_session(product.actor, NewSession(visibility='shared'))).id
    row, binding = await automation_fixtures.activate(ctx, security_profile_id=selected, session_id=chat)
    if change == 'disabled':
        await source_write(product, 'UPDATE moyai.security_profiles SET enabled=0 WHERE id=:id', id=selected)
    else:  # The chat is now wider than its workflow's policy.
        await profile(product, {'git_access': 'read'}, identity=selected, revision=2)
    async with product.database.sessions() as db:
        sessions = await db.scalar(select(func.count()).select_from(Session))
    assert (await automation_fixtures.occurrence(ctx, row, binding))['status'] == 'blocked'
    later = datetime.now(UTC) + timedelta(seconds=1)
    assert (await automation_fixtures.occurrence(ctx, row, binding, stamp=later))['status'] == 'blocked'
    async with product.database.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(Session)) == sessions
        assert await db.scalar(select(func.count()).select_from(Turn)) == 0
        current = await db.get(Binding, row['id'])
        assert (current.sync_state, current.last_error) == ('blocked', GOVERNANCE_BLOCKED)
    async with product.source.connect() as db:
        details = (await db.execute(text('SELECT detail FROM moyai.automation_runs'))).scalars().all()
    assert details == [GOVERNANCE_BLOCKED] * 2


@pytest_asyncio.fixture
async def governed_continuation(tmp_path):
    import test_product_continuation as continuation_fixtures
    async for product in continuation_fixtures.continuation.__wrapped__(tmp_path):
        attach(product)
        product.admit = lambda product=product: continuation_fixtures.admit(product)
        yield product


@pytest.mark.parametrize(('saved', 'git_access'), [
    ('{}', 'write'), (dump_policy(ProfilePolicy(git_access='none', tools=['read_file'])), 'none'), ('[]', None),
], ids=['ungoverned', 'governed', 'invalid'])
async def test_continuation_keeps_the_saved_policy_of_a_historical_governed_session(
        governed_continuation, saved, git_access):
    """Regression: the root read never selected runs.security_policy, so continuing dropped its ceiling."""
    product = governed_continuation
    # The earlier governance branch's column; '{}' marked an ungoverned session.
    await product.sql("ALTER TABLE moyai.runs ADD COLUMN security_policy text NOT NULL DEFAULT '{}'")
    await product.sql('UPDATE moyai.runs SET security_policy=:policy', policy=saved)
    if git_access is None:
        with pytest.raises(HTTPException) as refused:
            await product.admit()
        assert refused.value.status_code == 409
        async with product.database.sessions() as db:
            assert not list(await db.scalars(select(ProductSessionPolicy.session_id)))
        return
    result = await product.admit()
    async with product.database.sessions() as db:
        policy = await product.database.governance.policy(db, result['id'])
    assert policy.git_access == git_access
    assert policy.tools == (('read_file',) if git_access == 'none' else None)


async def test_historical_continuation_narrows_an_automatic_selection_after_binding(governed_continuation, monkeypatch):
    """Regression: a historical Slack thread's first message submitted its whole unfiltered catalog."""
    import test_product_continuation as continuation_fixtures

    from moyai.models import Turn
    product, seen = governed_continuation, []
    original = product.service.continue_for_admission

    async def continue_with_narrowing(db, actor, principal, source_id, body, **kwargs):
        async def narrow(db, session_id):
            seen.append(await db.get(ProductSessionPolicy, session_id) is not None)
            return body.model_copy(update={'connections': []})
        return await original(db, actor, principal, source_id, body, **kwargs, narrow=narrow)

    monkeypatch.setattr(product.service, 'continue_for_admission', continue_with_narrowing)
    # Unnarrowed, this unavailable selection would refuse the whole continuation.
    result = await continuation_fixtures.admit(product, connections=['f' * 32])
    assert seen == [True]
    async with product.database.sessions() as db:
        turn = await db.scalar(select(Turn).where(Turn.session_id == result['id']))
    assert json.loads(turn.connections) == []


async def test_effective_policy_is_read_once_per_transaction(governed, monkeypatch):
    """Regression: every tool and model check re-read the policy its transaction had already computed."""
    product, governance = governed, governed.database.governance
    session = await product.database.create_session(product.actor, NewSession())
    other = await product.database.create_session(product.actor, NewSession())
    profiles, reads = governance.product.profiles, []
    original = profiles.mandatory_in
    monkeypatch.setattr(profiles, 'mandatory_in', lambda read: reads.append(read) or original(read))
    async with product.database.sessions.begin() as db:
        await governance.principal(db, product.principal)
        first = await governance.policy(db, session.id)
        assert await governance.policy(db, session.id) is first and len(reads) == 1
        # Other sessions, including an unbound pre-governance one, reuse the
        # transaction's mandatory read; the unbound one stays unpinned for bind().
        await governance.policy(db, other.id)
        for _ in range(2):
            await governance.policy(db, 'unbound-session-id')
        assert len(reads) == 1
        assert 'unbound-session-id' not in governance._policies[db.sync_session.get_transaction()]
    await defaults(product, mandatory=await profile(product, {'tools': ['read_file']}))
    async with product.database.sessions.begin() as db:
        await governance.principal(db, product.principal)
        assert (await governance.policy(db, session.id)).tools == ('read_file',) and len(reads) == 2
        # A computer's network plan in the same transaction reuses the memo.
        assert (await governance.network_plan(session.id, db=db)).domains is None and len(reads) == 2


async def test_audit_routes_reject_bad_filters_with_the_tested_sentence(governed):
    """Regression: the routes validated filters apart from parse_filters and returned a raw error list."""
    class Unreached:
        def listing(self, *args):
            pytest.fail('Invalid audit filters reached the feed.')
        export = listing
    window = {'after': '2026-10-02T00:00:00Z', 'before': '2026-10-01T00:00:00Z'}
    async with governance_client(governed, audit=Unreached()) as client:
        for path in ('/api/admin/governance/audit', '/api/admin/governance/audit/export'):
            response = await client.get(path, params=window)
            assert (response.status_code, response.json()) == (422, {'detail': 'Choose an end time after the start time.'})


async def test_load_more_pages_carry_only_their_rows(governed):
    """Regression: cursor pages had to recompute facets and directory sections that the client discards."""
    class Audit:
        def listing(self, filters, cursor, limit):
            return {'entries': [], 'next_cursor': None, 'facets': None}
    class Directory:
        def router(self):
            from fastapi import APIRouter
            return APIRouter()
        def directory(self, cursor, limit, actor):
            return {'base_url': 'http://127.0.0.1:8787/scim/v2', 'users': {'items': [], 'next_cursor': None},
                    'groups': None, 'tokens': None, 'activity': None, 'can_create_tokens': True}
    async with governance_client(governed, audit=Audit(), scim=Directory()) as client:
        audit = await client.get('/api/admin/governance/audit', params={'cursor': 'next'})
        assert audit.status_code == 200 and audit.json()['facets'] is None
        page = (await client.get('/api/admin/scim', params={'cursor': 'next'})).json()
        assert (page['groups'], page['tokens'], page['activity']) == (None, None, None)


def github(repository_id):
    from moyai.contracts import Grant
    return Grant(f'github-{repository_id}', 'github', 1, '', policy={'product': {'repository_id': repository_id}})


async def test_repository_limits_admit_only_listed_github_grants(governed):
    from moyai.contracts import Grant
    product, governance = governed, governed.database.governance
    linear = Grant('linear', 'linear', 1, '', policy={'product': {'repository_id': None}})
    await defaults(product, await profile(product, {'repositories': [7]}))
    session = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        await governance.admission(db, session, principal, [github(7), linear])
        for refused in ([github(8)], [github(7), github(8)], [github(None)], [github(True)]):
            with pytest.raises(HTTPException, match='GitHub repository is not allowed') as caught:
                await governance.admission(db, session, principal, refused)
            assert caught.value.status_code == 403
    await defaults(product, await profile(product, {'repositories': []}))
    nothing = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        await governance.admission(db, nothing, principal, [linear])  # Other kinds are unaffected.
        with pytest.raises(HTTPException, match='GitHub repository is not allowed'):
            await governance.admission(db, nothing, principal, [github(7)])
        # Kind-level checks (workflow plugins) do not depend on a repository.
        assert governance.admits(await governance.policy(db, nothing.id), 'github')


async def test_legacy_four_key_bindings_load_unrestricted_and_the_mandatory_limit_still_applies(governed):
    """Immutable v24 bindings keep loading; a document missing one new key never reads as unrestricted."""
    from app.security_profiles import InvalidPolicy
    product, governance = governed, governed.database.governance
    product.database.governance = None  # Sessions that predate their binding, bound by hand below.
    legacy = await product.database.create_session(product.actor, NewSession())
    partial = await product.database.create_session(product.actor, NewSession())
    product.database.governance = governance
    stored = '{"connected_apps":null,"git_access":"read","network_domains":null,"tools":["read_file"]}'
    async with product.database.sessions.begin() as db:
        for session, policy in ((legacy, stored), (partial, stored[:-1] + ',"repositories":[7]}')):
            db.add(ProductSessionPolicy(session_id=session.id, profile_id='', profile_revision=0, policy=policy,
                                        inherited_from=None, family_root=session.id))
    async with product.database.sessions() as db:
        policy = await governance.policy(db, legacy.id)
        assert policy == ProfilePolicy(git_access='read', tools=['read_file']) and dump_policy(policy) == stored
        with pytest.raises(InvalidPolicy):
            await governance.policy(db, partial.id)
    await defaults(product, mandatory=await profile(product, {'repositories': [7], 'models': ['test']}))
    async with product.database.sessions() as db:
        policy = await governance.policy(db, legacy.id)
    assert (policy.repositories, policy.models, policy.git_access, policy.tools) == ((7,), ('test',), 'read', ('read_file',))


async def test_workspace_and_public_checkout_require_a_listed_repository(governed):
    """Environment snapshots skip preparation, so the workspace check governs the recorded ID."""
    from moyai.product_github_bootstrap import prepare_repository
    product, governance = governed, governed.database.governance
    _, _, prepared = await authority.active_turn(product)
    scope, url = prepared.scope, 'https://github.com/acme/app'
    async with product.database.sessions.begin() as db:
        await governance.workspace(db, scope, {'repo_url': url})  # Unrestricted: no ID needed.
    await defaults(product, mandatory=await profile(product, {'repositories': [7]}))
    async with product.database.sessions.begin() as db:
        await governance.workspace(db, scope, {'repo_url': url, 'repository_id': 7})
        await governance.workspace(db, scope, {'environment_build_id': 'build'})  # No repository at all.
    for context in ({'repo_url': url, 'repository_id': 8}, {'repo_url': url}, {'repository_id': 8},
                    {'environment_build_id': 'build', 'repo_url': 'https://github.com/acme/other', 'repository_id': 8}):
        with pytest.raises(HTTPException, match='repository exceeds'):
            async with product.database.sessions.begin() as db:
                await governance.workspace(db, scope, context)

    class Lookup(Exception):
        pass

    async def require_scope(scope):
        pass

    async def public_repository(*args, **kwargs):
        raise Lookup()
    service = SimpleNamespace(database=product.database, require_scope=require_scope, public_repository=public_repository)
    checkout = {'repo_url': url, 'working_dir': '/workspace/repo'}
    for target in (8, None):  # Refused before the credential-free provider lookup.
        with pytest.raises(HTTPException, match='repository exceeds'):
            await prepare_repository(service, scope, SimpleNamespace(), {**checkout, 'repository_id': target})
    with pytest.raises(Lookup):
        await prepare_repository(service, scope, SimpleNamespace(), {**checkout, 'repository_id': 7})


async def test_model_limits_choose_the_session_model_and_refuse_disallowed_turns(governed, monkeypatch):
    from moyai.contracts import NewMessage
    product = governed
    monkeypatch.setattr(product.database.settings, 'model_catalog', 'other,third')
    assert product.database.settings.models == ['test', 'other', 'third']
    await defaults(product, await profile(product, {'models': ['third', 'other']}))
    implicit = await product.database.create_session(product.actor, NewSession())
    assert implicit.model == 'other'  # The default is not allowed: the first allowed, in workspace order.
    assert (await product.database.create_session(product.actor, NewSession(model='third'))).model == 'third'

    async def counts():
        async with product.database.sessions() as db:
            return [await db.scalar(select(func.count()).select_from(table)) for table in (Session, ProductSessionPolicy)]
    before = await counts()
    with pytest.raises(HTTPException, match='model is not allowed') as refused:
        await product.database.create_session(product.actor, NewSession(model='test'))
    assert refused.value.status_code == 403 and await counts() == before  # Nothing is left behind.
    with pytest.raises(HTTPException, match='model is not allowed'):
        await product.database.submit(product.actor, implicit.id, NewMessage(
            prompt='Work', request_key='disallowed', model='test'))
    turn = await product.database.submit(product.actor, implicit.id, NewMessage(prompt='Work', request_key='allowed'))
    assert turn.model == 'other'
    await defaults(product, await profile(product, {'models': []}))
    with pytest.raises(HTTPException, match='No model enabled'):
        await product.database.create_session(product.actor, NewSession())


async def test_model_limit_refuses_paid_dispatch_even_without_spend_limits(inference):
    """Regression guard: the spend lookup returns early when nothing is limited."""
    ctx = inference
    governance = attach(ctx.product)
    with pytest.raises(TypeError):
        await governance.check_model(ctx.scope)  # The model is required, never skipped.
    await defaults(ctx.product, mandatory=await profile(ctx.product, {'models': ['other']}))
    with pytest.raises(HTTPException, match='model is not allowed'):
        await perform(ctx)
    assert not ctx.calls and not await requests(ctx)
    await defaults(ctx.product, mandatory=await profile(ctx.product, {'models': ['test']}))
    await perform(ctx, logical='allowed')
    assert len(ctx.calls) == len(await requests(ctx)) == 1


async def test_workflow_repositories_triggers_plugins_and_model_are_checked(governed):
    from moyai.product_automations import AutomationDefinition
    product, governance = governed, governed.database.governance
    selected = await profile(product, {'repositories': [7], 'models': ['test']})

    async def check(profile_id=selected, model='test', **fields):
        definition = AutomationDefinition(name='Governed', prompt='Work', security_profile_id=profile_id, **fields)
        async with product.database.sessions.begin() as db:
            principal = await governance.principal(db, product.principal.grant)
            await governance.workflow(db, principal, definition, model=model)

    def trigger(**event):
        return [{'id': 'push', 'event': {'provider': 'github', 'event': 'pull_request', **event}}]
    await check(repo_url='https://github.com/acme/app', github_repository_id=7, plugins=['github'],
                triggers=trigger(repository_id=7))
    for message, fields in (
        ('workflow repository exceeds', {'github_repository_id': 8}),
        ('workflow repository exceeds', {'repo_url': 'https://github.com/acme/app'}),
        ('trigger repository exceeds', {'triggers': trigger(repository_id=8)}),
        ('trigger repository exceeds', {'triggers': trigger(repository='acme/app')}),
        ('workflow model exceeds', {'model': 'other'}),
    ):
        with pytest.raises(HTTPException, match=message):
            await check(**fields)
    with pytest.raises(HTTPException, match='connections exceed'):
        await check(await profile(product, {'repositories': []}), plugins=['github'])
    # An agent-created workflow cannot exceed its session's repository or model limits.
    await defaults(product, await profile(product, {'repositories': [7], 'models': ['test']}))
    _, _, prepared = await authority.active_turn(product)
    wider = AutomationDefinition(name='Wider', prompt='Work', security_profile_id=await profile(product, {'models': ['test']}))
    with pytest.raises(HTTPException, match='cannot exceed'):
        async with product.database.sessions.begin() as db:
            await governance.workflow(db, product.principal, wider, scope=prepared.scope, model='test')
    async with product.database.sessions.begin() as db:
        await governance.workflow(db, product.principal, wider.model_copy(update={'security_profile_id': selected}),
                                  scope=prepared.scope, model='test')


async def test_plugin_expansion_keeps_only_listed_repositories_in_the_saved_context(automations, canonical_connections):
    """Regression guard: every installation repository was captured and then refused at each run's admission."""
    from moyai.product_automation_context_models import ProductAutomationExecutionContext as ExecutionContext
    ctx = automations
    product = ctx.product
    attach(product)
    await automation_fixtures.save_connection(ctx, 'github', kind='github_app', installation_id=1, repository_ids=[7, 8])
    selected = await profile(product, {'repositories': [7]})
    async with product.database.sessions() as db:
        grants = await canonical_connections.resolve_grants(
            product.actor.id, ['github'], shared_session=True, surface='automation', db=db)
    assert sorted(ProductGovernance.repository_of(grant) for grant in grants) == [7, 8]
    row, _ = await automation_fixtures.activate(ctx, plugins=['github'], security_profile_id=selected)
    async with product.database.sessions() as db:
        saved = await db.scalar(select(ExecutionContext).where(ExecutionContext.automation_id == row['id']))
    assert json.loads(saved.connection_ids) == [grant.id for grant in grants if ProductGovernance.repository_of(grant) == 7]


async def test_slack_auto_selection_drops_repositories_the_policy_excludes(automations, canonical_connections):
    ctx = automations
    product = ctx.product
    attach(product)
    await automation_fixtures.save_connection(ctx, 'github', kind='github_app', installation_id=1, repository_ids=[7, 8])
    await defaults(product, await profile(product, {'repositories': [7]}))
    session = await product.database.create_session(product.actor, NewSession(visibility='shared'))
    async with product.database.sessions() as db:
        grants = await canonical_connections.resolve_grants(
            product.actor.id, ['github'], shared_session=True, surface='slack', db=db)
    from moyai.contracts import NewMessage
    from moyai.product_slack_events import SlackEvents, SlackSubmission
    events = SlackEvents(SimpleNamespace(runtime=SimpleNamespace(database=product.database)))
    body = NewMessage(prompt='Work', request_key='slack', connections=[grant.id for grant in grants])
    submission = SlackSubmission(body, [], {grant.id: 'github' for grant in grants},
                                 {grant.id: ProductGovernance.repository_of(grant) for grant in grants})
    async with product.database.sessions.begin() as db:
        narrowed = await events._automatic(db, session.id, product.principal, submission)
    assert narrowed.connections == [grant.id for grant in grants if ProductGovernance.repository_of(grant) == 7]
