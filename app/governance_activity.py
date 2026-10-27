"""Metadata-only activity audit: sessions, messages, policy refusals and blocked runs.

Configuration changes, AI guardrail events and sign-in, refusal and sign-out
(sign_in.*) stay in governance_audit_events (app.governance_audit). Activity is
higher volume, so it has its own append-only table, governance_activity_events,
indexed by time, action, actor_key, resource_type and session. Native writes it
(moyai.product_activity_audit) by qualified name in the shared database, and
GovernanceAudit reads it as the 'activity' feed source.

ACTIVITY_ACTIONS is the static catalog: every action has one resource type, one
outcome and one details model. Details models forbid extra keys and hold only
enumerated values, booleans, small integers and identifiers, at most 2048 UTF-8
bytes, so prompts, titles, tool arguments, file names, tokens and policy payloads
cannot be stored. A tool name or model id that is not a plain identifier is stored
only as a digest, so an unusual configured model never blocks a message.
Validation never echoes the rejected value.

activity_id makes deterministic 128-bit ids: writers insert with ON CONFLICT(id)
DO NOTHING, so retried activities, workflow resets and repeated checks of one
denial record one row.
"""
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, NamedTuple
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

ACTIVITY_TABLE = 'governance_activity_events'
MAX_ACTIVITY_DETAILS = 2048
MAX_IDENTIFIER = 512
TOOL_NAME = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
IDENTIFIER = re.compile(r'[A-Za-z0-9_.:@/+-]{1,200}')

Identifier = Annotated[str, StringConstraints(pattern=IDENTIFIER.pattern.join('^$'))]
ToolName = Annotated[str, StringConstraints(pattern=TOOL_NAME.pattern.join('^$'))]
Digest = Annotated[str, StringConstraints(pattern=r'^[0-9a-f]{16}$')]
Kinds = Annotated[list[Identifier], Field(max_length=50)]
SpendScope = Literal['organization', 'user', 'session']


class _Details(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class NoDetails(_Details):
    pass


class SessionCreated(_Details):
    origin: Literal['user', 'slack', 'automation', 'delegation', 'swarm', 'continuation']
    visibility: Literal['private', 'shared']
    profile_id: Identifier | None = None
    profile_revision: int = Field(ge=0)
    inherited: bool


class SessionStopped(_Details):
    had_active_turn: bool


class MessageSubmitted(_Details):
    origin: Literal['user', 'slack', 'automation', 'delegation']
    mode: Literal['asap', 'when_idle']
    reply: bool
    steering: bool
    model: Identifier | None = None
    model_digest: Digest | None = None
    attachments: int = Field(ge=0, le=100)
    connection_kinds: Kinds


class ToolDenied(_Details):
    reason: Literal['role_permission', 'network_unenforceable', 'tool_disabled', 'connection_disabled', 'git_access']
    tool: ToolName | None = None
    tool_digest: Digest | None = None
    provider: Identifier | None = None
    permission: Identifier | None = None


class ModelDenied(_Details):
    reason: Literal['role_permission', 'network_unenforceable', 'model_policy', 'no_allowed_model', 'spend_limit']
    model: Identifier | None = None
    model_digest: Digest | None = None
    permission: Identifier | None = None
    scopes: Annotated[list[SpendScope], Field(max_length=3)] | None = None
    awaiting_cost: bool | None = None


class ConnectionDenied(_Details):
    reason: Literal['role_permission', 'connection_disabled', 'git_access', 'repository_policy']
    kind: Identifier
    write: bool
    permission: Identifier | None = None


class AdmissionDenied(_Details):
    reason: Literal['role_permission', 'network_unenforceable', 'connection_disabled', 'repository_policy']
    connection_kinds: Kinds | None = None
    permission: Identifier | None = None


class BindingDenied(_Details):
    reason: Literal['role_permission', 'network_unenforceable']
    permission: Identifier | None = None


class WorkspaceDenied(_Details):
    reason: Literal['role_permission', 'connection_disabled', 'repository_policy']
    permission: Identifier | None = None


class WorkflowDenied(_Details):
    reason: Literal['role_permission', 'network_unenforceable', 'connection_policy', 'repository_policy',
                    'model_policy', 'exceeds_session']
    automation_id: Identifier | None = None
    permission: Identifier | None = None


class ContinuationDenied(_Details):
    reason: Literal['continuation_wider', 'repository_policy', 'model_policy']
    automation_id: Identifier | None = None
    model: Identifier | None = None
    model_digest: Digest | None = None


class AutomationBlocked(_Details):
    occurrence_kind: Literal['schedule', 'event']
    reason: Literal['governance']


class ActionSpec(NamedTuple):
    resource_type: str
    outcome: Literal['success', 'denied', 'failed']
    details: type[_Details]


ACTIVITY_ACTIONS = {
    'session.created': ActionSpec('session', 'success', SessionCreated),
    'session.stopped': ActionSpec('session', 'success', SessionStopped),
    'session.archived': ActionSpec('session', 'success', NoDetails),
    'session.unarchived': ActionSpec('session', 'success', NoDetails),
    'session.deleted': ActionSpec('session', 'success', NoDetails),
    'session.restored': ActionSpec('session', 'success', NoDetails),
    'message.submitted': ActionSpec('message', 'success', MessageSubmitted),
    'policy.tool_denied': ActionSpec('policy', 'denied', ToolDenied),
    'policy.model_denied': ActionSpec('policy', 'denied', ModelDenied),
    'policy.connection_denied': ActionSpec('policy', 'denied', ConnectionDenied),
    'policy.admission_denied': ActionSpec('policy', 'denied', AdmissionDenied),
    'policy.binding_denied': ActionSpec('policy', 'denied', BindingDenied),
    'policy.workspace_denied': ActionSpec('policy', 'denied', WorkspaceDenied),
    'policy.workflow_denied': ActionSpec('policy', 'denied', WorkflowDenied),
    'policy.continuation_denied': ActionSpec('policy', 'denied', ContinuationDenied),
    'automation.blocked': ActionSpec('automation', 'denied', AutomationBlocked),
}
# Every action is named '<resource_type>.<verb>', as governance events are.
ACTIVITY_RESOURCE_TYPES = tuple(dict.fromkeys(spec.resource_type for spec in ACTIVITY_ACTIONS.values()))


class ActivityEvent(NamedTuple):
    """One validated row; the writer resolves actor and actor_key from actor_id."""
    id: str
    action: str
    outcome: str
    actor_id: str
    resource_type: str
    resource_id: str
    session_id: str
    details: str


def activity_id(action, *parts):
    """A deterministic 32-hex id for one logical event; parts are text."""
    return hashlib.sha256('\x1f'.join((action, *parts)).encode()).hexdigest()[:32]


def minute_bucket(instant=None):
    """The UTC minute ('2026-10-26T09:30') that bounds repeated HTTP-path refusals."""
    return (instant or datetime.now(UTC)).astimezone(UTC).strftime('%Y-%m-%dT%H:%M')


def _named(field, value, pattern):
    if isinstance(value, str) and pattern.fullmatch(value):
        return {field: value}
    return {field + '_digest': hashlib.sha256(str(value).encode()).hexdigest()[:16]}


def tool_fields(name):
    """{'tool': name} for an identifier-like tool name, else only its digest."""
    return _named('tool', name, TOOL_NAME)


def model_fields(model):
    """{'model': model} for an identifier-like model id, else only its digest."""
    return _named('model', model, IDENTIFIER)


def _identifier(value, name, *, empty=False):
    if not isinstance(value, str):
        raise TypeError(f'Activity audit {name} must be text.')
    if (not value and not empty) or len(value) > MAX_IDENTIFIER or '\x00' in value:
        raise ValueError(f'Activity audit {name} must have up to {MAX_IDENTIFIER} characters.')
    return value


def activity_event(action, *, actor_id, resource_id, session_id='', details=None, key=None):
    """A validated ActivityEvent; key (a tuple of text) makes its id deterministic.

    ValueError: an unknown action, details outside the action's model or over
    2048 bytes, or an empty or oversized identifier. TypeError: a non-text
    identifier. Messages never contain the rejected values.
    """
    spec = ACTIVITY_ACTIONS.get(action)
    if spec is None:
        raise ValueError('Unknown activity audit action.')
    try:
        model = spec.details.model_validate(details or {})
    except ValidationError:
        raise ValueError('Activity audit details do not match the action.') from None
    document = json.dumps(model.model_dump(exclude_none=True), sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False)
    if len(document.encode('utf-8')) > MAX_ACTIVITY_DETAILS or '\x00' in document:
        raise ValueError(f'Activity audit details exceed {MAX_ACTIVITY_DETAILS} bytes.')
    actor_id = _identifier(actor_id, 'actor', empty=True)
    resource_id = _identifier(resource_id, 'resource id')
    session_id = _identifier(session_id, 'session id', empty=True)
    if key is None:
        identity = uuid4().hex
    elif isinstance(key, tuple) and all(isinstance(part, str) for part in key):
        identity = activity_id(action, *key)
    else:
        raise TypeError('Activity audit keys are tuples of text.')
    return ActivityEvent(identity, action, spec.outcome, actor_id, spec.resource_type, resource_id, session_id,
                         document)
