"""Native governance boundaries on disposable PostgreSQL; no external provider calls."""
from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
import test_product_authority as authority
import test_product_automations as automation_fixtures
import test_product_inference as inference_fixtures
import test_product_skill_tools as skill_fixtures
from app.security_profiles import ProfilePolicy, SecurityProfiles, dump_policy
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from test_product_identity import google_cookie, request
from test_product_inference import perform, requests

from moyai.contracts import NewSession
from moyai.models import Session
from moyai.product_governance import ProductGovernance
from moyai.product_governance_models import ProductSessionPolicy
from moyai.product_schema import (
    GOAL_SCHEMA_VERSION,
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


async def test_network_policy_refused_atomically_before_native_session_exists(governed):
    selected = await profile(governed, {'network_domains': ['example.test']})
    await defaults(governed, selected)
    with pytest.raises(HTTPException, match='cannot enforce'):
        await governed.database.create_session(governed.actor, NewSession())
    async with governed.database.sessions() as db:
        assert not list(await db.scalars(select(Session.id)))
        assert not list(await db.scalars(select(ProductSessionPolicy.session_id)))


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
    for name in ('write_file', 'github_aaaaaaaa_create_pull_request', 'open_pull_request'):
        with pytest.raises(HTTPException):
            await governance.check_tool(scope, name, read_only=False)
    await member_role(product, ['sessions.read'])
    with pytest.raises(HTTPException):
        await governance.check_tool(scope, 'read_file', read_only=True)
    with pytest.raises(HTTPException):
        await product.database.create_session(product.actor, NewSession())


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
        await governance.workflow(db, principal, definition, scope=prepared.scope)
    await defaults(product)  # A source session cannot create an unrestricted workflow.
    definition.security_profile_id = ''
    with pytest.raises(HTTPException, match='cannot exceed'):
        async with product.database.sessions.begin() as db:
            await governance.workflow(db, product.principal, definition, scope=prepared.scope)
    principal = await member_role(product, ['sessions.create', 'sessions.read', 'automations.manage'])
    definition.security_profile_id = restricted
    async with product.database.sessions.begin() as db:
        await governance.workflow(db, principal, definition, previous=restricted)
    with pytest.raises(HTTPException):
        async with product.database.sessions.begin() as db:
            await governance.workflow(db, principal, definition)


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


async def test_zero_budget_and_pending_cost_block_before_provider_call(inference):
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
        with pytest.raises(HTTPException, match='spend limit'):
            await perform(ctx, logical='concurrent')
    finally:
        release.set()
        await first
    assert len(ctx.calls) == 1


async def test_governance_schema_adds_receipt_without_changing_v22(product_database):
    product = product_database
    await migrate_product_schema(product.source, schema=product.schema, source_schema='moyai', version=GOAL_SCHEMA_VERSION)
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
    from dataclasses import replace
    child_scope = replace(ctx.scope, session_id=child.id)
    with pytest.raises(HTTPException, match='spend limit'):
        await ctx.product.database.governance.check_model(child_scope)


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
    value = definition().model_dump(mode='json')
    value.pop('security_profile_id')
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


async def test_spend_management_without_read_permission_does_not_return_usage(governed):
    import httpx
    from fastapi import APIRouter, FastAPI

    from moyai.product_governance_routes import routes
    product = governed
    await member_role(product, ['spend.manage'])
    class ConfigurationOnly:
        def save(self, body, actor):
            return {'limits': [{'id': 'organization', 'limit_usd': 10}]}
        def delete(self, identity, revision, actor):
            return {'limits': []}
        def listing(self):
            pytest.fail('A limit writer without spend.read reached the usage response.')
    resources = product.database.governance.product
    resources.scim = SimpleNamespace(router=lambda: APIRouter())
    resources.spend_limits = ConfigurationOnly()
    app = FastAPI()
    app.include_router(routes(SimpleNamespace(product=resources, database=product.database)))
    cookie, csrf = google_cookie(product.adapter, sub=product.subject)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8787',
                                headers={'origin': 'http://127.0.0.1:8787', 'x-csrf-token': csrf}) as client:
        client.cookies.set('workspace_session', cookie)
        response = await client.put('/api/admin/spend-limits', json={'changes': [{'id': 'organization', 'limit_usd': 10.0, 'revision': 0}]})
        assert response.status_code == 200 and response.json() == {'limits': [{'id': 'organization', 'limit_usd': 10}]}
        response = await client.delete('/api/admin/spend-limits/user:person@example.test?revision=1')
        assert response.status_code == 200 and response.json() == {'limits': []}
        assert (await client.get('/api/admin/spend-limits')).status_code == 403
