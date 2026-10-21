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
    resources = product.database.governance.product
    resources.scim = SimpleNamespace(router=lambda: APIRouter())
    for name, service in services.items():
        setattr(resources, name, service)
    app = FastAPI()
    app.include_router(routes(SimpleNamespace(product=resources, database=database)))
    cookie, csrf = google_cookie(product.adapter, sub=product.subject)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8787',
                               headers={'origin': 'http://127.0.0.1:8787', 'x-csrf-token': csrf})
    client.cookies.set('workspace_session', cookie)
    return client


SPEND_ROW = {'id': 'organization', 'kind': 'organization', 'subject': '', 'limit_usd': 10.0, 'revision': 1,
             'updated_at': '2026-10-21T00:00:00Z', 'updated_by': 'admin@example.test'}


async def test_spend_management_without_read_permission_does_not_return_usage(governed):
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
        assert (await client.get('/api/admin/spend-limits')).status_code == 403


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


async def test_delegated_child_binds_the_parent_snapshot_not_a_newer_default(governed):
    from moyai.delegation import DelegationService
    product = governed
    selected = await profile(product, {'tools': ['read_file', 'shell'], 'git_access': 'read'})
    await defaults(product, selected)
    _, _, prepared = await authority.active_turn(product)
    await defaults(product)  # A newer unrestricted default must not reach the child.
    child = await DelegationService(product.database).start(prepared.scope, 'child', 'Work')
    async with product.database.sessions() as db:
        bound = await db.get(ProductSessionPolicy, child['session_id'])
        assert (bound.profile_id, bound.inherited_from) == (selected, prepared.scope.session_id)
        policy = await product.database.governance.policy(db, child['session_id'])
        assert policy.tools == ('read_file', 'shell') and policy.git_access == 'read'


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


async def test_no_git_access_refuses_github_grants_and_workflow_plugins(governed):
    from moyai.product_automations import AutomationDefinition
    product, governance = governed, governed.database.governance
    await defaults(product, await profile(product, {'git_access': 'none'}))
    session = await product.database.create_session(product.actor, NewSession())
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        await governance.admission(db, session, principal, [SimpleNamespace(kind='linear')])
        await governance.workflow(db, principal, AutomationDefinition(name='Issues', prompt='Work', plugins=['linear']))
        with pytest.raises(HTTPException, match='disabled by the session security policy'):
            await governance.admission(db, session, principal, [SimpleNamespace(kind='github')])
        with pytest.raises(HTTPException, match='connections exceed'):
            await governance.workflow(db, principal, AutomationDefinition(name='Git', prompt='Work', plugins=['github']))


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
        return [{'id': grant.id, 'kind': grant.kind} for grant in grants]

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
