"""Metadata-only governance audit events and the read-only governance audit feed.

Every successful governance change records exactly one event through
record_event_in on the same canonical connection, after its writer lock is held,
so a rolled-back change leaves no event. A native workflow (automation)
configuration change is such a change: mutate() inserts its event_values row
under the canonical writer lock it already holds. Native runtime outcomes, such
as a gateway AI guardrail refusal, insert event_values rows in the native
transaction that records the outcome instead. Sign-in events
(app.sign_in_audit) commit with the account write they describe, or take a
scoped write lock of their own; an event a client could repeat is keyed (an
Access sign-in or anonymous refusal per minute, a sign-out per session). Events
carry identifiers, actions, authenticated actors and bounded metadata; never
tokens, secrets, policy bodies or user content.
Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.

GovernanceAudit merges governance_audit_events with the activity audit
(governance_activity_events: sessions, messages, policy refusals and blocked
runs, see app.governance_activity) and the existing user_role_audit,
connection_audit and credential_audit tables into one feed ordered by
(created_at DESC, source, id DESC). Activity rows are append-only and written
without the writer lock: a trigger rejects UPDATE, so never add one. Reads never
take the writer lock: a page is one read-only snapshot (REPEATABLE READ READ
ONLY on PostgreSQL) in which each source is read through its (created_at, id)
index with the filters and a LIMIT in SQL. No index covers the governance
resource_type, but record_event_in requires '<resource_type>.<verb>' actions for
RESOURCE_TYPES, so a filter on one of them reads one governance keyset statement
per matching action through the action index. The activity table indexes
action, the folded actor (actor_key) and resource_type.
Legacy rows are normalized to fixed actions and identifiers; their free-text
action column is classified and never returned, and their details hold only
enumerated values.

Every writer stores datetime.isoformat() UTC text. record_event_in always writes
six fraction digits; db.now() and models.now() omit them at whole seconds. Both
spellings sort chronologically in byte order ('+' sorts before '.'), so SQL
compares the raw, indexed columns with an instant's lower ('...:00+00:00') and
upper ('...:00.000000+00:00') spellings, and cursors carry the canonical
six-digit spelling. Byte order is explicit: SQLite's BINARY collation is byte
order, and on PostgreSQL every feed comparison and ORDER BY uses COLLATE "C",
matching the COLLATE "C" feed indexes, so an ICU or libc database default (ICU
sorts '.' before '+') never reorders spellings or skips rows. Keyset pages never
repeat or skip a committed row. A row that commits after a later page was read,
with an older created_at, appears when the feed is reloaded.
"""
import csv
import hashlib
import hmac
import io
import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple
from uuid import uuid4

from fastapi import HTTPException
from itsdangerous import BadData, URLSafeTimedSerializer
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .governance_activity import ACTIVITY_ACTIONS, ACTIVITY_RESOURCE_TYPES, ACTIVITY_TABLE
from .identity_kinds import INDIVIDUAL_KINDS_SQL
from .schema_initializers import initialize_credentials, initialize_governance_activity, initialize_user_roles
from .schema_initializers import initialize_governance_audit as initialize_schema

MAX_ACTION = 64
MAX_RESOURCE_TYPE = 64
MAX_IDENTIFIER = 512
MAX_DETAILS_BYTES = 4096


def timestamp():
    """UTC ISO-8601 with fixed microseconds, so text order is chronological."""
    return datetime.now(UTC).isoformat(timespec='microseconds')


def _text(value, name, limit):
    if not isinstance(value, str):
        raise TypeError(f'Governance audit {name} must be text.')
    if not value or len(value) > limit or '\x00' in value:
        raise ValueError(f'Governance audit {name} must have 1 to {limit} characters.')
    return value


def _text_keys(value):
    # json.dumps would coerce 1 to "1", so {1: a, "1": b} could emit duplicates.
    if isinstance(value, Mapping):
        return all(isinstance(key, str) and _text_keys(item) for key, item in value.items())
    return not isinstance(value, (list, tuple)) or all(_text_keys(item) for item in value)


def _details(value):
    if value is None:
        return '{}'
    if not isinstance(value, Mapping):
        raise TypeError('Governance audit details must be a JSON object.')
    if not _text_keys(value):
        raise TypeError('Governance audit details need text keys and JSON values.')
    try:
        document = json.dumps(dict(value), sort_keys=True, separators=(',', ':'),
                              ensure_ascii=False, allow_nan=False)
    except TypeError:
        raise TypeError('Governance audit details need text keys and JSON values.') from None
    except ValueError:
        raise ValueError('Governance audit details cannot contain NaN or infinite numbers.') from None
    if len(document.encode('utf-8')) > MAX_DETAILS_BYTES:
        raise ValueError(f'Governance audit details exceed {MAX_DETAILS_BYTES} bytes.')
    return document


def _in_write_transaction(conn):
    # SQLite: an explicit BEGIN IMMEDIATE or an earlier write in this checkout.
    # PostgreSQL: Store's writer advisory lock is already held through commit.
    if isinstance(conn, sqlite3.Connection):
        return conn.in_transaction
    return getattr(conn, 'write_locked', False) is True


def event_values(action, actor, resource_type, resource_id, details=None):
    """(action, actor, resource_type, resource_id, details JSON) for one event.

    Validation happens before any SQL and never echoes values. TypeError: a
    field is not text or details are not a JSON object. ValueError: a field is
    empty, has NUL or exceeds its bound (action/resource_type 64 characters,
    actor/resource_id 512), details exceed 4096 UTF-8 bytes or hold NaN, a
    resource type in RESOURCE_TYPES has an action outside '<resource_type>.', or
    the resource type is one only the activity audit holds (ACTIVITY_ONLY_TYPES).
    """
    values = (_text(action, 'action', MAX_ACTION), _text(actor, 'actor', MAX_IDENTIFIER),
              _text(resource_type, 'resource type', MAX_RESOURCE_TYPE),
              _text(resource_id, 'resource id', MAX_IDENTIFIER), _details(details))
    # The feed's resource_type filter reads these rows through their actions,
    # and never reads this table for an activity-only type.
    if values[2] in ACTIVITY_ONLY_TYPES:
        raise ValueError('Record session, message and policy activity in the activity audit.')
    if values[2] in RESOURCE_TYPES and not values[0].startswith(values[2] + '.'):
        raise ValueError('Name governance actions <resource_type>.<verb>.')
    return values


def event_id(action, key):
    """The deterministic id of the one event an action records for key."""
    return hashlib.sha256(f'{action}/{key}'.encode()).hexdigest()[:32]


def record_event_in(conn, action, actor, resource_type, resource_id, details=None, *, key=None):
    """Insert one event in the caller's open write transaction and return its id.

    With a key the id is event_id(action, key) and a repeat inserts nothing, so
    an event a client can repeat (an Access sign-in per minute) is kept once.
    Raises event_values' TypeError and ValueError before any SQL. RuntimeError:
    the connection holds no write transaction.
    """
    values = event_values(action, actor, resource_type, resource_id, details)
    if not _in_write_transaction(conn):
        raise RuntimeError('Record governance audit events inside the mutation’s write transaction.')
    identity = uuid4().hex if key is None else event_id(action, key)
    conn.execute('''INSERT INTO governance_audit_events(id,action,actor,resource_type,resource_id,details,created_at)
        VALUES(?,?,?,?,?,?,?)''' + ('' if key is None else ' ON CONFLICT(id) DO NOTHING'),
                 (identity, *values, timestamp()))
    return identity


# Feed contract. Page sizes, the 100-day window and the 24-hour cursor are API
# limits; the export streams at most MAX_EXPORT_ROWS rows in EXPORT_PAGE batches.
DEFAULT_LIMIT, MAX_LIMIT = 50, 200
MAX_WINDOW = timedelta(days=100)
CURSOR_SALT = 'moyai-governance-audit-v2'
CURSOR_MAX_AGE = 86400
MAX_CURSOR = 2048
MAX_EXPORT_ROWS = 50_000
EXPORT_PAGE = 1000
MAX_FACET_ACTIONS = 200
EXPORT_FORMATS = ('csv', 'ndjson')
EXPORT_COLUMNS = ('created_at', 'source', 'action', 'actor', 'resource_type', 'resource_id', 'details')
# Spreadsheets evaluate cells starting with these; the quote keeps them literal text.
FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')
# Governance types, then the activity audit's: automation configuration changes
# are governance events and blocked runs are activity, so it appears once.
GOVERNANCE_TYPES = ('role', 'role_assignment', 'group_role', 'scim_user', 'scim_group', 'scim_token',
                    'security_profile', 'security_defaults', 'spend_limit', 'user_role', 'connection', 'credential',
                    'ai_guardrail', 'identity_binding', 'sign_in', 'automation')
# Resource types only the activity table holds (session, message, policy).
ACTIVITY_ONLY_TYPES = frozenset(ACTIVITY_RESOURCE_TYPES) - set(GOVERNANCE_TYPES)
RESOURCE_TYPES = (*GOVERNANCE_TYPES, *(kind for kind in ACTIVITY_RESOURCE_TYPES if kind not in GOVERNANCE_TYPES))

# Legacy free text maps to fixed actions; first match wins. Prefix rules cover
# texts that interpolate labels, repository ids or reasons, none of which leave.
CONNECTION_ACTIONS = (
    ('prefix', 'Connected ', 'connection.connected'),
    ('prefix', 'Disconnected', 'connection.disconnected'),
    ('prefix', 'Authorized', 'connection.authorized'),
    ('prefix', 'Updated organization connection policy', 'connection.policy_updated'),
    ('prefix', 'Paused', 'connection.paused'),
    ('prefix', 'Enabled', 'connection.enabled'),
    ('prefix', 'Updated selected permanent repository IDs', 'connection.repositories_updated'),
    ('prefix', 'Migrated the existing repository selection', 'connection.repositories_migrated'),
    ('prefix', 'Registered organization GitHub App', 'connection.app_registered'),
    ('prefix', 'Verified existing organization GitHub App', 'connection.app_verified'),
    ('prefix', 'Updated organization name', 'connection.organization_renamed'),
)
# Native credential writers prefix the same vocabulary with 'native '.
CREDENTIAL_ACTIONS = (
    ('prefix', 'saved ', 'credential.saved'),
    ('prefix', 'requested again', 'credential.rerequested'),
    ('exact', 'requested', 'credential.requested'),
    ('exact', 'reused', 'credential.reused'),
    ('exact', 'provided', 'credential.provided'),
    ('exact', 'declined', 'credential.declined'),
    ('prefix', 'satisfied via ', 'credential.satisfied'),
    ('exact', 'AWS cache refreshed', 'credential.aws_cache_refreshed'),
    ('prefix', 'authentication ', 'credential.failure_reported'),
    ('exact', 'updated', 'credential.updated'),
    ('exact', 'revoked', 'credential.revoked'),
    ('exact', 'personal Slack read', 'credential.slack_read'),
)
CONNECTION_FALLBACK, CREDENTIAL_FALLBACK = 'connection.changed', 'credential.changed'
CONNECTION_SLUGS = frozenset({slug for _, _, slug in CONNECTION_ACTIONS} | {CONNECTION_FALLBACK})
CREDENTIAL_SLUGS = frozenset({slug for _, _, slug in CREDENTIAL_ACTIONS} | {CREDENTIAL_FALLBACK})
LEGACY_ACTIONS = tuple(sorted(CONNECTION_SLUGS | CREDENTIAL_SLUGS | {'user_role.changed'}))
# Details from legacy text are enumerated values only (credentials.py Literals).
_CREDENTIAL_REASONS = frozenset({'expired', 'invalid', 'permission', 'unknown', 'unavailable',
                                 'revoked', 'active', 'not_found'})
_CREDENTIAL_SOURCES = frozenset({'browser_session', 'existing_credentials'})
_CREDENTIAL_SCOPES = frozenset({'session', 'personal', 'organization'})
_CREDENTIAL_LIFETIMES = frozenset({'session', 'persistent'})
_MAX_REPOSITORY_IDS = 100
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _literal(value):
    return "'" + value.replace("'", "''") + "'"


def _classifier(column, rules, fallback, prefixes=('',)):
    """Portable CASE over the legacy text; substr equality avoids LIKE wildcards."""
    cases = []
    for kind, text, slug in rules:
        tests = [f'{column}={_literal(prefix + text)}' if kind == 'exact'
                 else f'substr({column},1,{len(prefix + text)})={_literal(prefix + text)}' for prefix in prefixes]
        cases.append(f"WHEN {' OR '.join(tests)} THEN {_literal(slug)}")
    return f"(CASE {' '.join(cases)} ELSE {_literal(fallback)} END)"


def _instant(value):
    """Aware UTC instant from stored or submitted ISO-8601 text; naive means UTC."""
    if isinstance(value, str) and len(value) <= 64:
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise TypeError('Audit times must be ISO-8601 text.')
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value).astimezone(UTC)


def _spellings(instant):
    """Lowest and highest stored text for one instant, as SQL bounds."""
    return instant.isoformat(), instant.isoformat(timespec='microseconds')


def _canonical(instant):
    return instant.isoformat(timespec='microseconds')


class AuditFilters(BaseModel):
    """Exact action and resource type, case-insensitive exact actor, and a UTC window.

    after is inclusive and before exclusive; with both, before must be later and
    at most 100 days after after. Blank values mean no filter.
    """
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True, frozen=True)
    action: str | None = Field(default=None, max_length=MAX_ACTION)
    actor: str | None = Field(default=None, max_length=MAX_IDENTIFIER)
    resource_type: str | None = Field(default=None, max_length=MAX_RESOURCE_TYPE)
    after: datetime | None = None
    before: datetime | None = None

    @field_validator('action', 'actor', 'resource_type')
    @classmethod
    def _text_filter(cls, value, info):
        if not value:
            return None
        if '\x00' in value:
            raise ValueError('Audit filters cannot contain NUL characters.')
        return value.lower() if info.field_name == 'actor' else value

    @field_validator('after', 'before', mode='before')
    @classmethod
    def _time_filter(cls, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        try:
            return _instant(value.strip() if isinstance(value, str) else value)
        except (TypeError, ValueError, OverflowError):
            raise ValueError('Enter audit times as ISO-8601 UTC timestamps.') from None

    @model_validator(mode='after')
    def _window(self):
        if self.after is not None and self.before is not None:
            if self.before <= self.after:
                raise ValueError('Choose an end time after the start time.')
            if self.before - self.after > MAX_WINDOW:
                raise ValueError('Choose a date range of at most 100 days.')
        return self

    def contains(self, instant):
        return ((self.after is None or instant >= self.after)
                and (self.before is None or instant < self.before))

    def digest(self):
        """Binds cursors to these filters; the limit may change between pages."""
        values = [self.action, self.actor, self.resource_type,
                  *(None if value is None else _canonical(value) for value in (self.after, self.before))]
        return hashlib.sha256(json.dumps(values).encode()).hexdigest()[:32]


def parse_filters(**values) -> AuditFilters:
    """Filters from query values; failures are a 422 sentence that never echoes input."""
    try:
        return AuditFilters(**values)
    except ValidationError as exc:
        error = exc.errors()[0]
        reason = error.get('ctx', {}).get('error')
        raise HTTPException(422, str(reason) if error['type'] == 'value_error' and reason
                            else 'Check the audit filters and try again.') from None


def _filters(filters):
    if filters is None:
        return AuditFilters()
    if not isinstance(filters, AuditFilters):
        raise TypeError('Pass AuditFilters to the governance audit feed.')
    return filters


def _reload():
    return HTTPException(422, 'Reload the audit log and try again.')


def _governance_entry(row):
    try:
        details = json.loads(row['details'])
    except (TypeError, ValueError):
        details = None
    return (row['action'], row['actor'], row['resource_type'], row['resource_id'],
            details if isinstance(details, dict) else {})


def _user_role_entry(row):
    return ('user_role.changed', row['actor'], 'user_role', row['email'],
            {'previous': row['previous_role'] or None, 'replacement': row['role']})


def _activity_entry(row):
    try:
        details = json.loads(row['details'])
    except (TypeError, ValueError):
        details = None
    details = {**(details if isinstance(details, dict) else {}), 'outcome': row['outcome']}
    if row['session_id']:
        details['session_id'] = row['session_id']
    return row['action'], row['actor'], row['resource_type'], row['resource_id'], details


def _connection_entry(row):
    details: dict[str, Any] = {'provider': row['provider']}
    if row['action'] == 'connection.repositories_updated':
        ids = [part.strip() for part in row['summary'].partition(':')[2].split(',')]
        if 0 < len(ids) <= _MAX_REPOSITORY_IDS and all(part.isascii() and part.isdigit() and len(part) <= 20
                                                       for part in ids):
            details['repository_ids'] = ids
    return row['action'], row['actor'], 'connection', row['provider'], details


# Enumerated words that legacy credential texts interpolate, by position.
_CREDENTIAL_WORDS = {
    'credential.saved': ((1, 'scope', _CREDENTIAL_SCOPES), (2, 'lifetime', _CREDENTIAL_LIFETIMES)),
    'credential.rerequested': ((2, 'reason', _CREDENTIAL_REASONS),),  # requested again: <reason>
    'credential.failure_reported': ((1, 'reason', _CREDENTIAL_REASONS),),  # authentication <reason>
    'credential.satisfied': ((2, 'source', _CREDENTIAL_SOURCES),),  # satisfied via <source>
}


def _credential_entry(row):
    action = row['action']
    details: dict[str, Any] = {'secret_id': row['secret_id'] or None,
                               'session_id': row['run_id'].removeprefix('native:') or None}
    words = row['summary'].removeprefix('native ').replace(':', ' ').split()
    for index, key, allowed in _CREDENTIAL_WORDS.get(action, ()) if len(words) <= 3 else ():
        if index < len(words) and words[index] in allowed:
            details[key] = words[index]
    return action, row['actor'], 'credential', row['secret_id'], details


@dataclass(frozen=True)
class _Source:
    name: str
    select: str
    time: str
    ident: str
    action: str
    actions: frozenset[str] | None  # None: stored per row
    actor: str
    resource_type: str
    resource_types: frozenset[str] | None
    entry: Callable[[Any], tuple[str, str, str, str, dict]]
    integer_ids: bool = True
    actor_folded: bool = False  # The actor column is already unicode_lower(actor), and indexed.

    def statement(self, filters, position, limit):
        """Indexed keyset query for this source, or None when filters exclude it."""
        where, params = [], []
        for value, expression, known in ((filters.action, self.action, self.actions),
                                         (filters.resource_type, self.resource_type, self.resource_types)):
            if value is None:
                continue
            if known is not None and value not in known:
                return None
            if known is None or len(known) > 1:
                where.append(f'{expression}=?')
                params.append(value)
        if filters.actor is not None:
            where.append(f'{self.actor}=?' if self.actor_folded else f'unicode_lower({self.actor})=?')
            params.append(filters.actor)
        if filters.after is not None:
            where.append(f'{self.time}>=?')
            params.append(_spellings(filters.after)[0])
        if filters.before is not None:
            where.append(f'{self.time}<?')
            params.append(_spellings(filters.before)[0])
        if position is not None:
            instant, source, ident = position
            low, high = _spellings(instant)
            if self.name > source:  # Ties at the cursor instant follow it.
                where.append(f'{self.time}<=?')
                params.append(high)
            elif self.name < source:  # Ties at the cursor instant preceded it.
                where.append(f'{self.time}<?')
                params.append(low)
            else:
                where.append(f'({self.time}<=? AND ({self.time}<? OR {self.ident}<?))')
                params.extend((high, low, ident))
        clause = ' WHERE ' + ' AND '.join(where) if where else ''
        return (f'{self.select}{clause} ORDER BY {self.time} DESC,{self.ident} DESC LIMIT ?',
                (*params, limit))


_CONNECTION_ACTION = _classifier('a.action', CONNECTION_ACTIONS, CONNECTION_FALLBACK)
_CREDENTIAL_ACTION = _classifier('a.action', CREDENTIAL_ACTIONS, CREDENTIAL_FALLBACK, ('', 'native '))
# Credential actors are user ids; show the signed-in email when the id has one.
_CREDENTIAL_ACTOR = f"(CASE WHEN u.kind IN {INDIVIDUAL_KINDS_SQL} AND u.email<>'' THEN u.email ELSE a.actor_id END)"
# Sorted by name: ties at one instant are delivered in this order.
_SOURCES = tuple(sorted((
    _Source('activity',
            'SELECT e.id AS id,e.action AS action,e.outcome AS outcome,e.actor AS actor,'
            'e.resource_type AS resource_type,e.resource_id AS resource_id,e.session_id AS session_id,'
            f'e.details AS details,e.created_at AS created_at FROM {ACTIVITY_TABLE} e',
            'e.created_at', 'e.id', 'e.action', frozenset(ACTIVITY_ACTIONS), 'e.actor_key', 'e.resource_type',
            frozenset(ACTIVITY_RESOURCE_TYPES), _activity_entry, integer_ids=False, actor_folded=True),
    _Source('connections',
            f'SELECT a.id AS id,a.provider AS provider,{_CONNECTION_ACTION} AS action,a.action AS summary,'
            'a.actor AS actor,a.created_at AS created_at FROM connection_audit a',
            'a.created_at', 'a.id', _CONNECTION_ACTION, CONNECTION_SLUGS, 'a.actor',
            "'connection'", frozenset({'connection'}), _connection_entry),
    _Source('credentials',
            f'SELECT a.id AS id,a.secret_id AS secret_id,a.run_id AS run_id,a.action AS summary,'
            f'{_CREDENTIAL_ACTION} AS action,{_CREDENTIAL_ACTOR} AS actor,a.created_at AS created_at '
            'FROM credential_audit a LEFT JOIN users u ON u.id=a.actor_id',
            'a.created_at', 'a.id', _CREDENTIAL_ACTION, CREDENTIAL_SLUGS, _CREDENTIAL_ACTOR,
            "'credential'", frozenset({'credential'}), _credential_entry),
    _Source('governance',
            'SELECT e.id AS id,e.action AS action,e.actor AS actor,e.resource_type AS resource_type,'
            'e.resource_id AS resource_id,e.details AS details,e.created_at AS created_at '
            'FROM governance_audit_events e',
            'e.created_at', 'e.id', 'e.action', None, 'e.actor', 'e.resource_type', None, _governance_entry,
            integer_ids=False),
    _Source('user_roles',
            'SELECT a.id AS id,a.email AS email,a.previous_role AS previous_role,a.role AS role,a.actor AS actor,'
            'a.created_at AS created_at FROM user_role_audit a',
            'a.created_at', 'a.id', "'user_role.changed'", frozenset({'user_role.changed'}), 'a.actor',
            "'user_role'", frozenset({'user_role'}), _user_role_entry),
), key=lambda source: source.name))
_BY_NAME = {source.name: source for source in _SOURCES}
# PostgreSQL: byte-ordered text keys, the same expressions as the COLLATE "C"
# feed indexes, so backward index scans still serve each source's page.
_POSTGRES_SOURCES = tuple(replace(source, time=f'{source.time} COLLATE "C"',
                                  ident=source.ident if source.integer_ids else f'{source.ident} COLLATE "C"')
                          for source in _SOURCES)

# Skip scan over idx_governance_audit_action: one index probe per distinct action.
_ACTION_SCAN = '''WITH RECURSIVE seen(action,n) AS (
        SELECT (SELECT min(action) FROM governance_audit_events),1
        UNION ALL
        SELECT (SELECT min(g.action) FROM governance_audit_events g WHERE g.action>seen.action),seen.n+1
        FROM seen WHERE seen.action IS NOT NULL AND seen.n<?)
    SELECT action FROM seen WHERE action IS NOT NULL'''


def _statements_in(conn, source, filters, position, limit):
    """The source's keyset statements; a governance resource type reads each of its actions.

    Each statement filters on one '<resource_type>.' action, so it walks
    idx_governance_audit_action and keeps resource_type=? as a recheck. Types
    outside RESOURCE_TYPES (older layouts wrote 'security.defaults.updated' as
    SecurityDefaults) and an action list at its cap keep one unsplit statement.
    """
    if source.name == 'governance' and filters.resource_type in ACTIVITY_ONLY_TYPES:
        return []  # Only the activity table holds these; skip the action scan.
    if source.name == 'governance' and filters.action is None and filters.resource_type in RESOURCE_TYPES:
        found = [row['action'] for row in conn.execute(_ACTION_SCAN, (MAX_FACET_ACTIONS,)).fetchall()]
        if len(found) < MAX_FACET_ACTIONS:
            prefix = filters.resource_type + '.'
            return [source.statement(filters.model_copy(update={'action': action}), position, limit)
                    for action in found if action.startswith(prefix)]
    statement = source.statement(filters, position, limit)
    return [] if statement is None else [statement]


class _Item(NamedTuple):
    order: tuple
    position: tuple  # (instant, source, id): the cursor key
    entry: dict


def _order(position):
    """Ascending in feed order: newest instant, then source name, then highest id."""
    instant, source, ident = position
    micros = (instant - _EPOCH) // timedelta(microseconds=1)
    # Ids compare only within one source, so each source keeps one id type.
    rank = -ident if isinstance(ident, int) else (*(-ord(char) for char in ident), 1)
    return (-micros, source, rank)


def _item(source, row):
    try:
        instant = _instant(row['created_at'])
    except (TypeError, ValueError, OverflowError):
        raise RuntimeError('A governance audit source has an unreadable timestamp.') from None
    ident = int(row['id']) if source.integer_ids else str(row['id'])
    action, actor, resource_type, resource_id, details = source.entry(row)
    position = (instant, source.name, ident)
    return _Item(_order(position), position, {
        'id': str(ident), 'source': source.name, 'action': action, 'actor': actor,
        'resource_type': resource_type, 'resource_id': resource_id, 'details': details,
        'created_at': _canonical(instant)})


def _cell(value):
    return "'" + value if value.startswith(FORMULA_PREFIXES) else value


def _csv_line(cells):
    buffer = io.StringIO()
    csv.writer(buffer).writerow([_cell(value) for value in cells])
    return buffer.getvalue()


def _csv_entry(entry):
    details = json.dumps(entry['details'], sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return _csv_line([*(entry[column] for column in EXPORT_COLUMNS[:-1]), details])


def _ndjson_entry(entry):
    return json.dumps(entry, separators=(',', ':'), ensure_ascii=False) + '\n'


class GovernanceAudit:
    """Read-only, keyset-paginated audit feed and export over every audit source.

    secret signs cursors (24-hour expiry, bound to the filters). Reads use
    begin_read and never the writer lock. Methods block on the database; call
    them from a worker thread, never the event loop.
    """

    def __init__(self, store, secret):
        if isinstance(secret, str):
            secret = secret.encode()
        if not isinstance(secret, bytes) or not secret:
            raise ValueError('The governance audit feed needs a cursor signing secret.')
        self.store = store
        self.signer = URLSafeTimedSerializer(secret, salt=CURSOR_SALT)
        if store.schema_updates:
            # Auto-mode services create their own sources; verified schemas
            # already hold every source and are never altered here.
            initialize_user_roles(store)
            initialize_credentials(store)
            initialize_schema(store)
            initialize_governance_activity(store)

    def listing(self, filters=None, cursor=None, limit=DEFAULT_LIMIT):
        """{'entries', 'next_cursor', 'facets'}; facets only on the first page, None with a cursor.

        422 for a bad limit or cursor.
        """
        filters = _filters(filters)
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            raise HTTPException(422, f'Choose an audit page size from 1 to {MAX_LIMIT}.')
        position = self._position(cursor, filters) if cursor else None
        with self.store.connect() as conn:
            conn.begin_read()
            items, after = self._page_in(conn, filters, position, limit)
            facets = self._facets_in(conn) if position is None else None
        return {'entries': [item.entry for item in items],
                'next_cursor': self._cursor(after, filters) if after is not None else None,
                'facets': facets}

    def export(self, filters=None, fmt='csv') -> Iterator[str]:
        """CSV (header first) or NDJSON lines in feed order, at most MAX_EXPORT_ROWS.

        Each chunk holds one page of up to EXPORT_PAGE rows, so a caller that
        rechecks authority per chunk does so per page, not per row. Validation
        and the first page run before this returns, so failures are ordinary
        errors rather than a truncated download. Each later page opens its own
        read snapshot inside next(), so no connection is held between chunks of
        a slow download.
        """
        filters = _filters(filters)
        if fmt not in EXPORT_FORMATS:
            raise HTTPException(422, 'Choose csv or ndjson.')
        page = self._page(filters, None, min(EXPORT_PAGE, MAX_EXPORT_ROWS))
        return self._stream(filters, fmt, page)

    def _stream(self, filters, fmt, page):
        line = _csv_entry if fmt == 'csv' else _ndjson_entry
        header = _csv_line(EXPORT_COLUMNS) if fmt == 'csv' else ''
        sent = 0
        while True:
            items, position = page
            if chunk := header + ''.join(line(item.entry) for item in items):
                yield chunk
            header, sent = '', sent + len(items)
            if position is None or sent >= MAX_EXPORT_ROWS:
                return
            page = self._page(filters, position, min(EXPORT_PAGE, MAX_EXPORT_ROWS - sent))

    def _page(self, filters, position, limit):
        with self.store.connect() as conn:
            conn.begin_read()
            return self._page_in(conn, filters, position, limit)

    def _page_in(self, conn, filters, position, limit):
        """Merge per-source pages; return (items, position after them or None)."""
        items, boundary = [], None
        for source in _SOURCES if isinstance(conn, sqlite3.Connection) else _POSTGRES_SOURCES:
            for statement in _statements_in(conn, source, filters, position, limit + 1):
                rows = conn.execute(*statement).fetchall()
                fetched = [_item(source, row) for row in rows]
                if len(fetched) > limit and (boundary is None or fetched[-1].order < boundary.order):
                    # Rows of this statement beyond its last fetched row are unknown.
                    boundary = fetched[-1]
                items.extend(fetched)
        start = _order(position) if position is not None else None
        # SQL bounds are exact for writer spellings; this guard also places rows
        # stored in other ISO forms without repeating them.
        kept = sorted((item for item in items
                       if (start is None or item.order > start) and filters.contains(item.position[0])
                       and (boundary is None or item.order <= boundary.order)), key=lambda item: item.order)
        if len(kept) > limit:
            return kept[:limit], kept[limit - 1].position
        return kept, boundary.position if boundary is not None else None

    def _facets_in(self, conn):
        # Activity actions come from the static catalog: no scan of the larger table.
        found = {row['action'] for row in conn.execute(_ACTION_SCAN, (MAX_FACET_ACTIONS,)).fetchall()}
        return {'actions': sorted(found | set(LEGACY_ACTIONS) | set(ACTIVITY_ACTIONS)),
                'resource_types': list(RESOURCE_TYPES)}

    def _cursor(self, position, filters):
        instant, source, ident = position
        return self.signer.dumps({'v': 2, 'f': filters.digest(), 'k': [_canonical(instant), source, ident]})

    def _position(self, cursor, filters):
        if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR:
            raise _reload()
        try:
            state = self.signer.loads(cursor, max_age=CURSOR_MAX_AGE)
        except BadData:
            raise _reload() from None
        try:
            if (not isinstance(state, dict) or set(state) != {'v', 'f', 'k'} or type(state['v']) is not int
                    or state['v'] != 2 or not isinstance(state['f'], str)
                    or not hmac.compare_digest(state['f'], filters.digest())
                    or not isinstance(state['k'], list) or len(state['k']) != 3):
                raise ValueError()
            text, name, ident = state['k']
            source = _BY_NAME[name] if isinstance(name, str) else None
            if (source is None or not isinstance(text, str)
                    or (source.integer_ids and type(ident) is not int)
                    or (not source.integer_ids and not (isinstance(ident, str) and 0 < len(ident) <= MAX_IDENTIFIER))):
                raise ValueError()
            instant = _instant(text)
            if _canonical(instant) != text:
                raise ValueError()
        except (KeyError, TypeError, ValueError, OverflowError):
            raise _reload() from None
        return instant, name, ident
