"""The activity audit catalog: metadata-only details, deterministic ids and no echoed input."""
import json
from datetime import UTC, datetime

import pytest
from app.governance_activity import (
    ACTIVITY_ACTIONS,
    ACTIVITY_RESOURCE_TYPES,
    MAX_ACTIVITY_DETAILS,
    activity_event,
    activity_id,
    minute_bucket,
    model_fields,
    tool_fields,
)
from app.governance_audit import RESOURCE_TYPES

SECRET = 'sk-live-TOPSECRET prompt text'
MESSAGE = {'origin': 'user', 'mode': 'asap', 'reply': False, 'steering': False, 'model': 'test', 'attachments': 0,
           'connection_kinds': []}


def event(action='policy.tool_denied', **change):
    values = {'actor_id': 'google:owner', 'resource_id': 's' * 32, 'session_id': 's' * 32,
              'details': {'reason': 'tool_disabled', 'tool': 'shell'}, **change}
    return activity_event(action, **values)


def test_every_action_names_its_resource_type_and_one_outcome():
    for action, spec in ACTIVITY_ACTIONS.items():
        assert action.startswith(spec.resource_type + '.')
        assert spec.outcome == ('denied' if spec.resource_type == 'policy' or action == 'automation.blocked'
                                else 'success')
        assert spec.details.model_config['extra'] == 'forbid' and spec.details.model_config['strict']
    # The feed's resource_type filter reaches every activity type through the governance catalog.
    assert set(ACTIVITY_RESOURCE_TYPES) == {'session', 'message', 'policy', 'automation'}
    assert set(ACTIVITY_RESOURCE_TYPES) <= set(RESOURCE_TYPES)


def test_events_hold_only_validated_metadata():
    built = event()
    assert built.action == 'policy.tool_denied' and built.outcome == 'denied' and built.resource_type == 'policy'
    assert json.loads(built.details) == {'reason': 'tool_disabled', 'tool': 'shell'}
    # Omitted optional values are left out, not stored as null.
    assert built.details == '{"reason":"tool_disabled","tool":"shell"}'
    assert len(built.id) == 32 and built.id != event().id  # Without a key, every event is new.


@pytest.mark.parametrize(('action', 'change'), [
    ('policy.unknown', {}),
    ('sign_in.succeeded', {}),  # Sign-in lives in the governance audit, not the activity table.
    ('policy.tool_denied', {'details': {'reason': 'tool_disabled', 'prompt': SECRET}}),
    ('policy.tool_denied', {'details': {'reason': SECRET}}),
    ('policy.tool_denied', {'details': {'reason': 'tool_disabled', 'tool': SECRET}}),
    ('policy.tool_denied', {'details': {'reason': 'tool_disabled', 'permission': 'a\x00b'}}),
    ('policy.model_denied', {'details': {'reason': 'spend_limit', 'scopes': ['organization', SECRET]}}),
    ('policy.model_denied', {'details': {'reason': 'spend_limit', 'awaiting_cost': 'yes'}}),
    ('message.submitted', {'details': {**MESSAGE, 'attachments': True}}),
    ('message.submitted', {'details': {**MESSAGE, 'connection_kinds': ['github'] * 51}}),
    ('session.created', {'details': {'origin': 'user', 'visibility': 'shared', 'profile_revision': 1,
                                     'inherited': False, 'title': SECRET}}),
    ('session.deleted', {'details': {'note': SECRET}}),
])
def test_unknown_actions_and_free_text_are_refused_without_echo(action, change):
    with pytest.raises(ValueError) as refused:
        event(action, **change)
    assert SECRET not in str(refused.value)
    # No chained validation error carries the input into logs or tracebacks.
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None or refused.value.__suppress_context__


def test_identifiers_are_bounded_text():
    for change in ({'resource_id': ''}, {'resource_id': 'r' * 513}, {'session_id': 'a\x00'}):
        with pytest.raises(ValueError, match='Activity audit'):
            event(**change)
    with pytest.raises(TypeError):
        event(actor_id=7)
    with pytest.raises(TypeError):
        event(key=('session', 7))
    assert event(actor_id='', session_id='').actor_id == ''


def test_details_are_limited_to_2048_bytes():
    kinds = ['k' * 40 + str(index) for index in range(50)]
    details = {**MESSAGE, 'connection_kinds': kinds}
    with pytest.raises(ValueError, match=f'exceed {MAX_ACTIVITY_DETAILS} bytes'):
        event('message.submitted', details=details)
    assert event('message.submitted', details={**details, 'connection_kinds': kinds[:30]})


def test_keyed_ids_are_deterministic_per_action_and_key():
    first = event(key=('s' * 32, 't' * 32, 'shell', 'tool_disabled'))
    assert first.id == event(key=('s' * 32, 't' * 32, 'shell', 'tool_disabled')).id
    assert first.id == activity_id('policy.tool_denied', 's' * 32, 't' * 32, 'shell', 'tool_disabled')
    assert first.id != event(key=('s' * 32, 'u' * 32, 'shell', 'tool_disabled')).id
    assert first.id != event('policy.connection_denied', details={'reason': 'git_access', 'kind': 'github',
                                                                   'write': True},
                             key=('s' * 32, 't' * 32, 'shell', 'tool_disabled')).id
    # Separators keep ('ab', 'c') and ('a', 'bc') apart.
    assert activity_id('session.created', 'ab', 'c') != activity_id('session.created', 'a', 'bc')


def test_tool_names_outside_the_identifier_pattern_are_digests():
    assert tool_fields('github_create_pull_request') == {'tool': 'github_create_pull_request'}
    hidden = tool_fields('run ' + SECRET)
    assert set(hidden) == {'tool_digest'} and len(hidden['tool_digest']) == 16
    assert json.loads(event(details={'reason': 'tool_disabled', **hidden}).details)['tool_digest'] == hidden['tool_digest']


def test_model_ids_outside_the_identifier_pattern_are_digests():
    # A configured model id never blocks a message: an unusual one is kept only as a digest.
    assert model_fields('openai/gpt-6-astra') == {'model': 'openai/gpt-6-astra'}
    hidden = model_fields('team model ' + SECRET)
    assert set(hidden) == {'model_digest'} and len(hidden['model_digest']) == 16
    details = {key: value for key, value in MESSAGE.items() if key != 'model'}
    built = event('message.submitted', details={**details, **hidden})
    assert json.loads(built.details)['model_digest'] == hidden['model_digest'] and SECRET not in built.details
    assert json.loads(event('policy.model_denied', details={'reason': 'model_policy', **hidden}).details) == {
        'reason': 'model_policy', **hidden}
    with pytest.raises(ValueError):
        event('message.submitted', details={**details, 'model': 'team model ' + SECRET})


def test_minute_buckets_are_utc_minutes():
    instant = datetime(2026, 10, 26, 9, 30, 59, 999999, tzinfo=UTC)
    assert minute_bucket(instant) == '2026-10-26T09:30'
    assert minute_bucket(instant.astimezone().replace(microsecond=0)) == '2026-10-26T09:30'
