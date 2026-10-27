"""Activity audit of sessions, messages, policy refusals and workflows on disposable PostgreSQL.

Refusals keep their status and message, record one policy.* row per turn (or
per actor and minute outside a turn) on the canonical pool, and fail open.
Session and message activity commits with its change. No row holds a prompt,
title, tool argument or policy payload.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import test_product_automations as automation_fixtures
import test_product_governance as governance_fixtures
from fastapi import HTTPException
from sqlalchemy import select, text
from test_product_authority import active_turn
from test_product_governance import attach, defaults, member_role, profile, source_write
from test_product_inference import perform

from moyai import product_activity_audit
from moyai.contracts import NewMessage, NewSession
from moyai.product_activity_audit import ProductActivityAudit

pytestmark = pytest.mark.skipif(not os.getenv('MOYAI_TEST_POSTGRES'), reason='Disposable local PostgreSQL required.')
admitted_product = governance_fixtures.admitted_product
governed = governance_fixtures.governed
automations = governance_fixtures.automations
inference = governance_fixtures.inference
SENTINEL = 'SENTINEL-private-prompt-' + uuid4().hex


def audited(product):
    governance = attach(product)
    governance.activity = ProductActivityAudit(product.adapter, product.source)
    return governance


async def activity(product, action=None):
    async with product.source.connect() as db:
        rows = (await db.execute(text(
            'SELECT * FROM moyai.governance_activity_events ORDER BY created_at,id'))).mappings().all()
    return [{**row, 'details': json.loads(row['details'])} for row in rows if action in {None, row['action']}]


async def governance_events(product, prefix):
    async with product.source.connect() as db:
        rows = (await db.execute(text(
            "SELECT * FROM moyai.governance_audit_events WHERE action LIKE :prefix ORDER BY created_at,id"),
            {'prefix': prefix + '%'})).mappings().all()
    return [{**row, 'details': json.loads(row['details'])} for row in rows]


async def refused(check):
    with pytest.raises(HTTPException) as error:
        await check()
    return error.value.status_code, error.value.detail


async def test_a_refused_tool_is_recorded_once_per_turn_with_its_error_unchanged(governed):
    product = governed
    governance = audited(product)
    await defaults(product, await profile(product, {'tools': ['read_file']}))
    _, _, prepared = await active_turn(product)
    scope = prepared.scope
    await governance.check_tool(scope, 'read_file', read_only=True)
    # governance_tool, the activity interceptor and a retried attempt check one call.
    for _ in range(3):
        assert await refused(lambda: governance.check_tool(scope, 'shell', read_only=False)) == (
            403, 'This tool is disabled by the session security policy.')
    [row] = await activity(product, 'policy.tool_denied')
    assert {key: row[key] for key in ('action', 'outcome', 'actor', 'actor_key', 'actor_id', 'resource_type',
                                      'resource_id', 'session_id', 'client', 'details')} == {
        'action': 'policy.tool_denied', 'outcome': 'denied', 'actor': 'admin@example.test',
        'actor_key': 'admin@example.test', 'actor_id': product.user_id, 'resource_type': 'policy',
        'resource_id': scope.session_id, 'session_id': scope.session_id, 'client': '',
        'details': {'reason': 'tool_disabled', 'tool': 'shell'}}
    # A workflow reset keeps the turn; another turn is another row.
    assert await refused(lambda: governance.check_tool(replace(scope, history_segment=2), 'shell'))
    later = replace(scope, turn_id=uuid4().hex)
    results = await asyncio.gather(*(governance.check_tool(later, 'shell') for _ in range(2)), return_exceptions=True)
    assert all(isinstance(result, HTTPException) for result in results)  # Concurrent identical denials.
    assert len(await activity(product, 'policy.tool_denied')) == 2
    # A tool name that is not an identifier is kept only as a digest.
    assert await refused(lambda: governance.check_tool(scope, 'shell; cat ' + SENTINEL))
    assert set((await activity(product, 'policy.tool_denied'))[-1]['details']) == {'reason', 'tool_digest'}
    assert SENTINEL not in json.dumps(await activity(product), default=str)


async def test_role_network_and_model_refusals_record_their_reasons(governed, monkeypatch):
    product = governed
    audited(product)
    from app import governance_activity
    settings = product.database.settings
    monkeypatch.setattr(governance_activity, 'minute_bucket', lambda: '2026-10-26T09:30')
    monkeypatch.setattr(settings, 'model_catalog', 'other')
    selected = await profile(product, {'models': ['test']})
    await defaults(product, selected)
    session = await product.database.create_session(product.actor, NewSession())
    assert await refused(lambda: product.database.submit(product.actor, session.id, NewMessage(
        prompt=SENTINEL, request_key='disallowed', model='other'))) == (
        403, 'This model is not allowed by the session security policy.')
    monkeypatch.setattr(settings, 'network_policy_enforcement', 'off')
    await defaults(product, await profile(product, {'network_domains': ['example.test']}))
    for _ in range(2):  # Outside a turn, one row per actor, reason and minute.
        status, detail = await refused(lambda: product.database.create_session(product.actor, NewSession()))
        assert status == 409 and detail.startswith('This deployment cannot enforce network allowlists yet.')
    await defaults(product)
    await member_role(product, ['sessions.read'])
    assert await refused(lambda: product.database.create_session(product.actor, NewSession())) == (
        403, 'Your workspace role does not allow this action.')
    rows = [(row['action'], row['resource_id'], row['session_id'], row['details']) for row in await activity(product)]
    assert rows == [
        ('session.created', session.id, session.id, {'origin': 'user', 'visibility': 'shared', 'profile_id': selected,
                                                      'profile_revision': 1, 'inherited': False}),
        ('policy.model_denied', session.id, session.id, {'reason': 'model_policy', 'model': 'other'}),
        ('policy.binding_denied', 'workspace', '', {'reason': 'network_unenforceable'}),
        ('policy.binding_denied', 'workspace', '', {'reason': 'role_permission', 'permission': 'sessions.create'}),
    ]
    # A refused session leaves neither its session nor a session.created row.
    assert len(await activity(product, 'session.created')) == 1


async def test_every_other_refusal_site_records_one_row_with_its_error_unchanged(governed):
    from moyai.product_automations import AutomationDefinition
    product = governed
    governance = audited(product)
    await defaults(product, await profile(product, {'connected_apps': ['linear']}))
    session, _, prepared = await active_turn(product)
    scope, github = prepared.scope, SimpleNamespace(kind='github', policy={})
    narrower = await profile(product, {'connected_apps': [], 'tools': ['read_file']})
    workflow, automation = 'a' * 32, 'b' * 32
    async with product.database.sessions.begin() as db:
        principal = await governance.principal(db, product.principal.grant)
        refusals = [
            await refused(lambda: governance.admission(db, session, principal, [github], turn_id=scope.turn_id)),
            await refused(lambda: governance.workspace(db, scope, {'repo_url': 'https://github.com/acme/app'})),
            await refused(lambda: governance.workflow(db, principal, AutomationDefinition(
                name=SENTINEL, prompt=SENTINEL, plugins=['github']), model='test', automation_id=workflow)),
            await refused(lambda: governance.continuation(db, session.id, narrower, actor_id=principal.id,
                                                          automation_id=automation)),
        ]
    refusals.append(await refused(lambda: governance.connection(scope, github)))
    assert refusals == [
        (403, 'A selected connection is disabled by the session security policy.'),
        (403, 'The repository exceeds the session security policy.'),
        (403, 'The workflow connections exceed its security policy.'),
        (403, ('This chat allows more than the workflow security policy. '
               'Choose a chat started under that policy, or a new chat for each run.')),
        (403, 'This connection is disabled by the session security policy.'),
    ]
    rows = [row for row in await activity(product) if row['outcome'] == 'denied']
    assert {row['action']: (row['resource_id'], row['session_id'], row['details']) for row in rows} == {
        'policy.admission_denied': (session.id, session.id, {'reason': 'connection_disabled',
                                                             'connection_kinds': ['github']}),
        'policy.workspace_denied': (session.id, session.id, {'reason': 'connection_disabled'}),
        'policy.workflow_denied': (workflow, '', {'reason': 'connection_policy', 'automation_id': workflow}),
        'policy.continuation_denied': (session.id, session.id, {'reason': 'continuation_wider',
                                                                'automation_id': automation}),
        'policy.connection_denied': (session.id, session.id, {'reason': 'connection_disabled', 'kind': 'github',
                                                              'write': False}),
    }
    assert len(rows) == 5 and {row['actor'] for row in rows} == {'admin@example.test'}
    assert SENTINEL not in json.dumps(rows, default=str)


async def test_network_and_new_session_model_refusals_keep_only_identifiers(governed, monkeypatch):
    import hashlib
    product = governed
    governance = audited(product)
    settings = product.database.settings
    _, _, prepared = await active_turn(product)
    scope = prepared.scope
    monkeypatch.setattr(settings, 'network_policy_enforcement', 'off')
    await defaults(product, mandatory=await profile(product, {'network_domains': ['example.test']}))
    for check in (lambda: governance.check_tool(scope, 'read_file', read_only=True),
                  lambda: governance.check_model(scope, model='test')):
        status, detail = await refused(check)
        assert status == 409 and detail.startswith('This deployment cannot enforce network allowlists yet.')
    # A configured model id that is not an identifier.
    odd = 'Odd model ' + SENTINEL
    monkeypatch.setattr(settings, 'model_catalog', odd)
    await defaults(product, await profile(product, {'models': ['test']}))
    assert await refused(lambda: product.database.create_session(product.actor, NewSession(model=odd))) == (
        403, 'This model is not allowed by the session security policy.')
    rows = [(row['action'], row['resource_id'], row['session_id'], row['details'])
            for row in await activity(product) if row['outcome'] == 'denied']
    assert rows == [
        ('policy.tool_denied', scope.session_id, scope.session_id,
         {'reason': 'network_unenforceable', 'tool': 'read_file'}),
        ('policy.model_denied', scope.session_id, scope.session_id,
         {'reason': 'network_unenforceable', 'model': 'test'}),
        # A refused new session names no session, and never the model id itself.
        ('policy.model_denied', 'workspace', '',
         {'reason': 'model_policy', 'model_digest': hashlib.sha256(odd.encode()).hexdigest()[:16]}),
    ]
    assert SENTINEL not in json.dumps(await activity(product), default=str)


async def test_a_text_reply_to_a_waiting_question_records_one_reply(governed):
    from test_questions import waiting
    product = governed
    audited(product)
    session, original, _ = await waiting(SimpleNamespace(database=product.database), product.actor)
    body = NewMessage(prompt=SENTINEL, request_key='typed-answer', reply_to=original.id)
    reply = await product.database.submit(product.actor, session.id, body)
    assert (await product.database.submit(product.actor, session.id, body)).id == reply.id  # A retried reply.
    rows = await activity(product, 'message.submitted')
    assert [(row['resource_id'], row['session_id'], row['details']['reply']) for row in rows] == [
        (original.id, session.id, False), (reply.id, session.id, True)]
    assert rows[1]['details'] == {'origin': 'user', 'mode': 'when_idle', 'reply': True, 'steering': False,
                                  'model': 'test', 'attachments': 0, 'connection_kinds': []}
    assert SENTINEL not in json.dumps(await activity(product), default=str)


async def test_lost_refusal_records_fail_open_within_their_budget(governed, monkeypatch, caplog):
    product = governed
    governance = audited(product)
    await defaults(product, await profile(product, {'tools': ['read_file']}))
    _, _, prepared = await active_turn(product)

    class Exhausted:
        def begin(self):
            raise TimeoutError('pool exhausted')

    class Slow:
        @asynccontextmanager
        async def begin(self):
            await asyncio.sleep(30)
            yield

    monkeypatch.setattr(product_activity_audit, 'DETACHED_TIMEOUT', 0.2)
    with caplog.at_level('WARNING', logger='moyai.product_activity_audit'):
        for engine in (Exhausted(), Slow()):
            governance.activity.engine = engine
            started = time.monotonic()
            async with product.database.sessions.begin() as db:
                assert await refused(lambda: governance.check_tool(
                    replace(prepared.scope, turn_id=uuid4().hex), 'shell', db=db)) == (
                    403, 'This tool is disabled by the session security policy.')
                # The caller's transaction is untouched and still usable.
                assert await db.scalar(select(1)) == 1
            assert time.monotonic() - started < 5
    assert caplog.text.count('Policy refusal policy.tool_denied was not recorded: TimeoutError') == 2
    assert not await activity(product, 'policy.tool_denied')


async def test_sessions_and_messages_are_recorded_once_without_content(governed):
    product = governed
    audited(product)
    database, actor = product.database, product.actor
    session = await database.create_session(actor, NewSession(title=SENTINEL, visibility='private'))
    body = NewMessage(prompt=SENTINEL, request_key='first', mode='asap')
    turn = await database.submit(actor, session.id, body)
    assert (await database.submit(actor, session.id, body)).id == turn.id  # A repeated request key.
    assert (await database.claim_next()).id == turn.id
    await database.stop(actor, session.id)
    await database.stop(actor, session.id)  # The same turn is still stopping.
    other = await database.create_session(actor, NewSession(title=SENTINEL))
    for change in (database.delete_session, database.delete_session, database.restore_session,
                   database.restore_session):
        await change(actor, other.id)  # The repeats are idempotent no-ops.
    rows = await activity(product)
    assert [(row['action'], row['resource_id'], row['session_id']) for row in rows] == [
        ('session.created', session.id, session.id), ('message.submitted', turn.id, session.id),
        ('session.stopped', session.id, session.id), ('session.created', other.id, other.id),
        ('session.deleted', other.id, other.id), ('session.restored', other.id, other.id)]
    assert rows[0]['details'] == {'origin': 'user', 'visibility': 'private', 'profile_revision': 0,
                                  'inherited': False}
    assert rows[1]['details'] == {'origin': 'user', 'mode': 'asap', 'reply': False, 'steering': False,
                                  'model': 'test', 'attachments': 0, 'connection_kinds': []}
    assert rows[2]['details'] == {'had_active_turn': True}
    assert {row['actor'] for row in rows} == {'admin@example.test'}
    assert SENTINEL not in json.dumps(rows, default=str)


async def test_a_delegated_child_records_its_origin_and_parent(governed):
    product = governed
    audited(product)
    parent = await product.database.create_session(product.actor, NewSession())
    child = await product.database.create_session(product.actor, NewSession(), inherited_from=parent.id,
                                                  origin='delegation')
    [*_, row] = await activity(product, 'session.created')
    assert (row['resource_id'], row['details']['origin'], row['details']['inherited']) == (child.id, 'delegation', True)


async def test_a_spend_limit_refusal_is_recorded_once_across_attempts_without_amounts(inference):
    ctx = inference
    audited(ctx.product)
    await source_write(ctx.product, "INSERT INTO moyai.spend_limits VALUES('user-default','user-default','',0,1,'owner','now')")
    for attempt in (1, 2, 3):
        with pytest.raises(HTTPException, match='spend limit'):
            await perform(ctx, logical='refused', attempt=attempt)
    [row] = await activity(ctx.product)
    assert row['action'] == 'policy.model_denied' and row['session_id'] == ctx.scope.session_id
    assert row['details'] == {'reason': 'spend_limit', 'model': 'test', 'scopes': ['user'], 'awaiting_cost': False}
    assert not ctx.calls


async def test_workflow_changes_are_audited_in_the_writer_and_blocked_runs_once(automations):
    from datetime import UTC, datetime, timedelta

    from moyai.product_automations import Mutation
    ctx = automations
    product = ctx.product
    audited(product)
    selected = await profile(product, {})
    row, binding = await automation_fixtures.activate(ctx, security_profile_id=selected)
    pause = Mutation(revision=row['revision'], request_key='pause-' + uuid4().hex)
    paused = await ctx.service.mutate(ctx.grant, 'pause', row['id'], pause)
    assert await ctx.service.mutate(ctx.grant, 'pause', row['id'], pause) == paused  # A replayed request key.
    events = await governance_events(product, 'automation.')
    assert [(event['action'], event['actor'], event['resource_type'], event['resource_id']) for event in events] == [
        (f'automation.{verb}', 'admin@example.test', 'automation', row['id'])
        for verb in ('created', 'migrated', 'paused')]
    assert events[1]['details'] == {
        'revision': 2, 'native_state': 'active', 'security_profile_id': selected, 'trigger_kinds': ['schedule'],
        'connection_kinds': [], 'has_repository': False, 'via': 'http'}
    assert 'Summarize synthetic results' not in json.dumps(events)

    # A run the workflow's policy no longer admits is blocked, and recorded once.
    disabled = await profile(product, {})
    scheduled, binding = await automation_fixtures.activate(ctx, security_profile_id=disabled)
    await source_write(product, 'UPDATE moyai.security_profiles SET enabled=0 WHERE id=:id', id=disabled)
    stamp = datetime.now(UTC)
    for _ in range(2):  # A retried occurrence reuses its receipt.
        assert (await automation_fixtures.occurrence(ctx, scheduled, binding, stamp=stamp))['status'] == 'blocked'
    later = stamp + timedelta(seconds=1)
    assert (await automation_fixtures.occurrence(ctx, scheduled, binding, stamp=later))['status'] == 'blocked'
    [blocked] = await activity(product, 'automation.blocked')
    assert (blocked['actor'], blocked['resource_id'], blocked['outcome'], blocked['details']) == (
        'admin@example.test', scheduled['id'], 'denied', {'occurrence_kind': 'schedule', 'reason': 'governance'})


async def test_an_agent_workflow_change_names_its_session(automations):
    from test_product_automations import definition

    from moyai.product_automations import Save
    ctx = automations
    product = ctx.product
    audited(product)
    _, _, prepared = await active_turn(product)
    scope = prepared.scope
    saved = await ctx.service.mutate(
        ctx.grant, 'create', None, Save(definition=definition(), revision=0, request_key='agent-create'),
        operation_scope=f'session:{scope.session_id}', scope=scope)
    [event] = await governance_events(product, 'automation.')
    assert (event['action'], event['actor'], event['resource_id']) == (
        'automation.created', 'admin@example.test', saved['id'])
    assert (event['details']['via'], event['details']['session_id']) == ('agent', scope.session_id)


async def test_archive_records_only_a_changed_value(runtime, actor):
    from moyai.api import COOKIE, create_app
    session = await runtime.database.create_session(actor, NewSession())
    recorded = []

    async def record(db, action, **event):
        recorded.append((action, event['resource_id'], event['session_id']))

    runtime.database.governance = SimpleNamespace(record=record)
    token, csrf = runtime.security.issue_session(actor.id, actor.auth_version)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(runtime, run_dispatcher=False)), base_url='http://test',
            cookies={COOKIE: token}, headers={'x-moyai-csrf': csrf, 'origin': 'http://test'},
        ) as client:
            for archived in (True, True, False, False):
                response = await client.patch(f'/api/sessions/{session.id}', json={'archived': archived})
                assert response.status_code == 200, response.text
    finally:
        runtime.database.governance = None
    assert recorded == [('session.archived', session.id, session.id), ('session.unarchived', session.id, session.id)]


async def test_stopping_a_team_member_records_its_stop_once(runtime, actor):
    from moyai.swarm_contracts import NewSwarm
    root, _ = await runtime.database.swarms.start(actor, NewSwarm(
        prompt='Investigate the test dataset.', request_key='team', workers=2, visibility='private'))
    member = (await runtime.database.swarms.view(actor, root.id))['members'][1]['session_id']
    recorded = []

    async def record(db, action, **event):
        recorded.append((action, event['session_id'], event['details']))

    runtime.database.governance = SimpleNamespace(record=record)
    try:
        # The member Stop takes the team path, which stops every member.
        await runtime.database.stop(actor, member)
        await runtime.database.stop(actor, member)  # Already stopped: nothing more.
    finally:
        runtime.database.governance = None
    assert recorded == [('session.stopped', member, {'had_active_turn': False})]
