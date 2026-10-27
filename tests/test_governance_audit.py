"""Governance audit feed and export on SQLite or --postgres-backend.

The feed merges governance_audit_events and the activity audit
(governance_activity_events) with the legacy user_role_audit, connection_audit
and credential_audit tables. Pages are keyset-paginated over
(created_at DESC, source, id DESC), read in one read-only snapshot and never
take the canonical writer lock.
"""
import csv
import io
import json
import os
import random
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app import governance_audit
from app.database import PostgresConnection, SQLiteConnection
from app.db import Store
from app.governance_activity import ACTIVITY_ACTIONS, activity_event
from app.governance_audit import (
    EXPORT_COLUMNS,
    LEGACY_ACTIONS,
    RESOURCE_TYPES,
    AuditFilters,
    GovernanceAudit,
    event_values,
    parse_filters,
    record_event_in,
)
from app.schema_migrations import initialize_components
from fastapi import HTTPException
from itsdangerous.timed import TimestampSigner

SECRET = b'governance-audit-test-secret'
BASE = datetime(2026, 10, 16, 9, 30, tzinfo=UTC)
SOURCE_ORDER = ('activity', 'connections', 'credentials', 'governance', 'user_roles')
RELOAD = 'Reload the audit log and try again.'


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path)
    initialize_components(store)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def audit(store):
    return GovernanceAudit(store, SECRET)


def legacy(instant):
    """db.now()/models.now(): no fraction digits at whole seconds."""
    return instant.isoformat()


def fixed(instant):
    """record_event_in: always six fraction digits."""
    return instant.isoformat(timespec='microseconds')


def governance_row(store, instant, *, action='role.created', actor='owner@example.com', resource_type='role',
                   resource_id='auditor', details=None, ident=None):
    ident = ident or uuid4().hex
    store.execute('''INSERT INTO governance_audit_events(id,action,actor,resource_type,resource_id,details,created_at)
        VALUES(?,?,?,?,?,?,?)''', (ident, action, actor, resource_type, resource_id,
                                   json.dumps(details or {}, sort_keys=True, separators=(',', ':')), fixed(instant)))
    return ident


def activity_row(store, instant, action='session.created', *, actor='Owner@Example.com', actor_id='google:owner',
                 resource_id=None, session_id=None, details=None, key=None):
    """One validated activity event, as the native writer stores it."""
    session_id = uuid4().hex if session_id is None else session_id
    details = details if details is not None else {
        'session.created': {'origin': 'user', 'visibility': 'shared', 'profile_revision': 0, 'inherited': False},
        'session.stopped': {'had_active_turn': True},
        'policy.tool_denied': {'reason': 'tool_disabled', 'tool': 'shell'},
        'message.submitted': {'origin': 'user', 'mode': 'asap', 'reply': False, 'steering': False, 'model': 'test',
                              'attachments': 0, 'connection_kinds': []},
    }.get(action, {})
    event = activity_event(action, actor_id=actor_id, resource_id=resource_id or session_id or 'workspace',
                           session_id=session_id, details=details, key=key)
    store.execute('''INSERT INTO governance_activity_events(id,action,outcome,actor,actor_key,actor_id,resource_type,
        resource_id,session_id,details,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING''',
                  (event.id, event.action, event.outcome, actor, actor.lower(), event.actor_id, event.resource_type,
                   event.resource_id, event.session_id, event.details, fixed(instant)))
    return event.id


def user_role_row(store, instant, *, email='bob@example.com', previous='member', role='admin',
                  actor='owner@example.com'):
    store.execute('INSERT INTO user_role_audit(email,previous_role,role,actor,created_at) VALUES(?,?,?,?,?)',
                  (email, previous, role, actor, legacy(instant)))


def connection_row(store, instant, *, provider='github', action='Connected for the organization',
                   actor='Organization admin'):
    store.execute('INSERT INTO connection_audit(provider,action,actor,created_at) VALUES(?,?,?,?)',
                  (provider, action, actor, legacy(instant)))


def credential_row(store, instant, *, actor_id='google:dana', secret_id='s' * 32, action='reused',
                   run_id='native:session-1'):
    store.execute('INSERT INTO credential_audit(actor_id,secret_id,action,run_id,created_at) VALUES(?,?,?,?,?)',
                  (actor_id, secret_id, action, run_id, legacy(instant)))


def user(store, ident, kind, email):
    stamp = legacy(BASE)
    store.execute('INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                  (ident, kind, email, email or ident, stamp, stamp))


def oracle(store):
    """Every source row as (source, id) in feed order, computed from raw rows."""
    keys = []
    for source, table in (('activity', 'governance_activity_events'), ('connections', 'connection_audit'),
                          ('credentials', 'credential_audit'), ('governance', 'governance_audit_events'),
                          ('user_roles', 'user_role_audit')):
        for row in store.rows(f'SELECT id,created_at FROM {table}'):
            keys.append((datetime.fromisoformat(row['created_at']), source, row['id']))
    # Stable sorts, least significant first: id DESC, then source ASC, then instant DESC.
    keys.sort(key=lambda key: (key[1], key[2]), reverse=True)  # Ids compare only within a source.
    keys.sort(key=lambda key: SOURCE_ORDER.index(key[1]))
    keys.sort(key=lambda key: key[0], reverse=True)
    return [(source, str(ident)) for _, source, ident in keys]


def pages(audit, filters=None, limit=7):
    seen, cursor = [], None
    for _ in range(1000):
        page = audit.listing(filters, cursor, limit)
        assert len(page['entries']) <= limit
        seen.extend((entry['source'], entry['id']) for entry in page['entries'])
        cursor = page['next_cursor']
        if cursor is None:
            return seen
    raise AssertionError('Pagination did not finish.')


def records(chunks):
    """NDJSON export records; each is exactly one newline-terminated line."""
    text = ''.join(chunks)
    assert text == '' or text.endswith('\n')
    return [json.loads(line) for line in text.split('\n')[:-1]]


def detail(call):
    with pytest.raises(HTTPException) as rejected:
        call()
    assert rejected.value.status_code == 422
    return rejected.value.detail


def test_constructor_initializes_every_source_on_a_core_store(tmp_path):
    store = Store(tmp_path / 'core-only')
    try:
        audit = GovernanceAudit(store, SECRET)
        assert audit.listing(None) == {'entries': [], 'next_cursor': None, 'facets': {
            'actions': sorted({*LEGACY_ACTIONS, *ACTIVITY_ACTIONS}), 'resource_types': list(RESOURCE_TYPES)}}
        for secret in (b'', '', None, 7):
            with pytest.raises(ValueError, match='signing secret'):
                GovernanceAudit(store, secret)
    finally:
        store.close()


def test_entries_normalize_every_source_without_raw_legacy_text(store, audit):
    user(store, 'google:dana', 'google', 'dana@example.com')
    with store.connect() as conn:
        conn.begin_write()
        event = record_event_in(conn, 'role.created', 'owner@example.com', 'role', 'auditor',
                                {'permissions': ['audit.read'], 'previous': None})
    at = datetime(2020, 1, 1, tzinfo=UTC)  # Before the event recorded now.
    user_role_row(store, at, previous='')
    connection_row(store, at, action='Connected octo-org (installation 991): PR publishing; merges blocked')
    connection_row(store, at, action='Updated selected permanent repository IDs: 11, 22')
    connection_row(store, at, provider='organization', action='Updated organization name')
    connection_row(store, at, provider='linear', action='Something new and unclassified')
    credential_row(store, at, action='requested again: sk-live-TOPSECRET', run_id='run-1')
    credential_row(store, at, action='native saved organization persistent', secret_id='')
    credential_row(store, at, action='authentication expired', actor_id='slack:T1:U1')
    credential_row(store, at, action='satisfied via browser_session', secret_id='')
    credential_row(store, at, action='requested again: expired')
    credential_row(store, at, action='personal note: hunter2')
    page = audit.listing(AuditFilters())
    assert 'sk-live' not in json.dumps(page) and 'octo-org' not in json.dumps(page) and 'hunter2' not in json.dumps(page)
    [first, *rest] = page['entries']
    assert first == {'id': event, 'source': 'governance', 'action': 'role.created', 'actor': 'owner@example.com',
                     'resource_type': 'role', 'resource_id': 'auditor',
                     'details': {'permissions': ['audit.read'], 'previous': None},
                     'created_at': store.rows('SELECT created_at FROM governance_audit_events')[0]['created_at']}
    stamp = '2020-01-01T00:00:00.000000+00:00'
    assert {entry['created_at'] for entry in rest} == {stamp}
    shown = [{key: entry[key] for key in ('source', 'action', 'actor', 'resource_type', 'resource_id', 'details')}
             for entry in rest]
    credential = {'source': 'credentials', 'resource_type': 'credential'}
    assert shown == [
        {'source': 'connections', 'action': 'connection.changed', 'actor': 'Organization admin',
         'resource_type': 'connection', 'resource_id': 'linear', 'details': {'provider': 'linear'}},
        {'source': 'connections', 'action': 'connection.organization_renamed', 'actor': 'Organization admin',
         'resource_type': 'connection', 'resource_id': 'organization', 'details': {'provider': 'organization'}},
        {'source': 'connections', 'action': 'connection.repositories_updated', 'actor': 'Organization admin',
         'resource_type': 'connection', 'resource_id': 'github',
         'details': {'provider': 'github', 'repository_ids': ['11', '22']}},
        {'source': 'connections', 'action': 'connection.connected', 'actor': 'Organization admin',
         'resource_type': 'connection', 'resource_id': 'github', 'details': {'provider': 'github'}},
        {**credential, 'action': 'credential.changed', 'actor': 'dana@example.com', 'resource_id': 's' * 32,
         'details': {'secret_id': 's' * 32, 'session_id': 'session-1'}},
        {**credential, 'action': 'credential.rerequested', 'actor': 'dana@example.com', 'resource_id': 's' * 32,
         'details': {'secret_id': 's' * 32, 'session_id': 'session-1', 'reason': 'expired'}},
        {**credential, 'action': 'credential.satisfied', 'actor': 'dana@example.com', 'resource_id': '',
         'details': {'secret_id': None, 'session_id': 'session-1', 'source': 'browser_session'}},
        {**credential, 'action': 'credential.failure_reported', 'actor': 'slack:T1:U1', 'resource_id': 's' * 32,
         'details': {'secret_id': 's' * 32, 'session_id': 'session-1', 'reason': 'expired'}},
        {**credential, 'action': 'credential.saved', 'actor': 'dana@example.com', 'resource_id': '',
         'details': {'secret_id': None, 'session_id': 'session-1', 'scope': 'organization', 'lifetime': 'persistent'}},
        {**credential, 'action': 'credential.rerequested', 'actor': 'dana@example.com', 'resource_id': 's' * 32,
         'details': {'secret_id': 's' * 32, 'session_id': 'run-1'}},
        {'source': 'user_roles', 'action': 'user_role.changed', 'actor': 'owner@example.com',
         'resource_type': 'user_role', 'resource_id': 'bob@example.com',
         'details': {'previous': None, 'replacement': 'admin'}},
    ]
    assert all(isinstance(entry['id'], str) for entry in page['entries']) and page['next_cursor'] is None


def test_pagination_is_total_and_stable_across_sources_ties_and_spellings(store, audit):
    random.seed(22)
    writers = (governance_row, user_role_row, connection_row, credential_row, activity_row)
    for index in range(150):
        # Few distinct instants: many ties within and across sources, and whole
        # seconds stored as both '...:00+00:00' and '...:00.000000+00:00'.
        instant = BASE + timedelta(seconds=random.randint(0, 4), microseconds=random.choice((0, 0, 1, 999999)))
        writers[index % 5](store, instant)
    expected = oracle(store)
    assert len(expected) == len(set(expected)) == 150
    assert pages(audit) == expected
    assert pages(audit, limit=1) == expected and pages(audit, limit=200) == expected
    first = audit.listing(None, None, 9)
    # Newer commits after the first page never shift later pages.
    for writer in writers:
        writer(store, BASE + timedelta(minutes=5))
    rest, cursor = [], first['next_cursor']
    while cursor:
        page = audit.listing(None, cursor, 9)
        rest.extend((entry['source'], entry['id']) for entry in page['entries'])
        cursor = page['next_cursor']
    assert [(entry['source'], entry['id']) for entry in first['entries']] + rest == expected
    assert pages(audit) == oracle(store)


def test_filters_are_pushed_into_every_source(store, audit):
    user(store, 'google:dana', 'google', 'dana@example.com')
    user(store, 'cloudflare:erin', 'cloudflare', 'erin@example.com')
    whole = BASE  # A whole second: stored as both spellings below.
    governance_row(store, whole, action='role.created', actor='Owner@Example.com')
    governance_row(store, whole + timedelta(days=1), action='scim_user.deactivated', resource_type='scim_user',
                   actor='idp:entra')
    user_role_row(store, whole, actor='OWNER@example.com')
    user_role_row(store, whole - timedelta(microseconds=1), actor='someone@example.com')
    connection_row(store, whole, action='Connected for the organization')
    connection_row(store, whole + timedelta(hours=1), action='Connected octo: PR publishing')
    connection_row(store, whole + timedelta(hours=2), action='Disconnected from the organization')
    credential_row(store, whole, action='reused')
    credential_row(store, whole + timedelta(hours=3), action='native reused', actor_id='cloudflare:erin')
    credential_row(store, whole + timedelta(hours=4), action='revoked', actor_id='slack:T1:U1')

    def listed(**values):
        return [(entry['source'], entry['action'], entry['actor']) for entry in
                audit.listing(parse_filters(**values), limit=200)['entries']]

    assert listed(action='connection.connected') == [('connections', 'connection.connected', 'Organization admin')] * 2
    assert listed(action='credential.reused') == [('credentials', 'credential.reused', 'erin@example.com'),
                                                  ('credentials', 'credential.reused', 'dana@example.com')]
    assert listed(action='user_role.changed', actor='owner@EXAMPLE.com') == [
        ('user_roles', 'user_role.changed', 'OWNER@example.com')]
    assert listed(actor=' owner@example.com ') == [('governance', 'role.created', 'Owner@Example.com'),
                                                   ('user_roles', 'user_role.changed', 'OWNER@example.com')]
    assert listed(actor='DANA@example.com') == [('credentials', 'credential.reused', 'dana@example.com')]
    assert listed(actor='slack:t1:u1') == [('credentials', 'credential.revoked', 'slack:T1:U1')]
    assert listed(resource_type='scim_user') == [('governance', 'scim_user.deactivated', 'idp:entra')]
    assert [row[0] for row in listed(resource_type='credential')] == ['credentials'] * 3
    assert listed(action='unknown.action') == [] and listed(resource_type='user_role', action='role.created') == []
    # after is inclusive and before exclusive, for both stored spellings of BASE.
    at_base = {('connections', 'connection.connected', 'Organization admin'),
               ('credentials', 'credential.reused', 'dana@example.com'),
               ('governance', 'role.created', 'Owner@Example.com'),
               ('user_roles', 'user_role.changed', 'OWNER@example.com')}
    assert set(listed(after='2026-10-16T09:30:00Z', before='2026-10-16T09:30:00.000001Z')) == at_base
    assert set(listed(after='2026-10-16T09:30:00+00:00', before='2026-10-16T09:30:00.5+00:00')) == at_base
    assert ('user_roles', 'user_role.changed', 'someone@example.com') not in listed(after='2026-10-16T09:30:00Z')
    assert listed(before='2026-10-16T09:30:00Z') == [('user_roles', 'user_role.changed', 'someone@example.com')]
    assert listed(before='2026-10-16T11:30:00+02:00') == listed(before='2026-10-16T09:30:00')
    assert len(listed(after='2026-10-16T09:30:00.000001Z')) == 5


@pytest.mark.parametrize(('values', 'message'), [
    ({'after': 'yesterday'}, 'Enter audit times as ISO-8601 UTC timestamps.'),
    ({'before': '2026-13-01T00:00:00Z'}, 'Enter audit times as ISO-8601 UTC timestamps.'),
    ({'after': 1760000000}, 'Enter audit times as ISO-8601 UTC timestamps.'),
    ({'after': '2026-10-01T00:00:00.' + '0' * 60}, 'Enter audit times as ISO-8601 UTC timestamps.'),
    ({'after': '2026-10-02T00:00:00Z', 'before': '2026-10-02T00:00:00Z'}, 'Choose an end time after the start time.'),
    ({'after': '2026-10-02T00:00:00Z', 'before': '2026-10-01T00:00:00Z'}, 'Choose an end time after the start time.'),
    ({'after': '2026-07-08T00:00:00Z', 'before': '2026-10-16T00:00:00.000001Z'}, 'Choose a date range of at most 100 days.'),
    ({'action': 'x' * 65}, 'Check the audit filters and try again.'),
    ({'actor': 'a\x00b'}, 'Audit filters cannot contain NUL characters.'),
    ({'actor': 7}, 'Check the audit filters and try again.'),
    ({'format': 'csv'}, 'Check the audit filters and try again.'),
])
def test_invalid_filters_are_422_sentences_without_input(values, message):
    assert detail(lambda: parse_filters(**values)) == message


def test_filter_values_are_normalized():
    window = parse_filters(after='2026-07-08T00:00:00Z', before='2026-10-16T00:00:00Z')
    assert window.before - window.after == timedelta(days=100)
    assert parse_filters(after='2026-10-01').after == datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_filters(after='2026-10-01T02:00:00+02:00').after == datetime(2026, 10, 1, tzinfo=UTC)
    blank = parse_filters(action='', actor='  ', resource_type=None, after='', before=' ')
    assert blank == AuditFilters() and blank.digest() == AuditFilters().digest()
    assert parse_filters(actor=' Owner@Example.COM ').actor == 'owner@example.com'
    with pytest.raises(TypeError):
        GovernanceAudit.listing(object.__new__(GovernanceAudit), {'action': 'role.created'})


@pytest.mark.parametrize('limit', [0, 201, -1, True, '5', 5.0])
def test_page_size_is_bounded(audit, limit):
    assert detail(lambda: audit.listing(None, None, limit)) == 'Choose an audit page size from 1 to 200.'


def test_cursor_rejects_tampering_other_secrets_expiry_and_other_filters(store, audit, monkeypatch):
    for second in range(6):
        governance_row(store, BASE + timedelta(seconds=second))
        user_role_row(store, BASE + timedelta(seconds=second))
    filters = parse_filters(after='2026-10-16T00:00:00Z')
    cursor = audit.listing(filters, None, 3)['next_cursor']
    assert cursor and len(audit.listing(filters, cursor, 3)['entries']) == 3
    assert audit.listing(filters, cursor, 50)['next_cursor'] is None  # The page size may change.
    tampered = cursor[:10] + ('A' if cursor[10] != 'A' else 'B') + cursor[11:]
    assert detail(lambda: audit.listing(filters, tampered)) == RELOAD
    assert detail(lambda: GovernanceAudit(store, b'another-secret').listing(filters, cursor)) == RELOAD
    for other in (AuditFilters(), parse_filters(after='2026-10-16T00:00:00.000001Z'),
                  parse_filters(after='2026-10-16T00:00:00Z', actor='owner@example.com'),
                  parse_filters(after='2026-10-16T00:00:00Z', action='role.created')):
        assert detail(lambda other=other: audit.listing(other, cursor)) == RELOAD
    assert detail(lambda: audit.listing(filters, 'x' * 2049)) == RELOAD
    assert detail(lambda: audit.listing(filters, 'not-a-cursor')) == RELOAD
    stamp, digest = '2026-10-16T09:30:01.000000+00:00', filters.digest()
    for state in ({'v': 1, 'f': digest, 'k': [stamp, 'governance', 'a' * 32]},
                  {'v': True, 'f': digest, 'k': [stamp, 'governance', 'a' * 32]},
                  {'v': 2, 'f': digest, 'k': [stamp, 'governance', 'a' * 32], 'extra': 1},
                  {'v': 2, 'f': digest, 'k': [stamp, 'runs', 1]},
                  {'v': 2, 'f': digest, 'k': [stamp, 'governance', 7]},
                  {'v': 2, 'f': digest, 'k': [stamp, 'user_roles', '7']},
                  {'v': 2, 'f': digest, 'k': [stamp, 'user_roles', True]},
                  {'v': 2, 'f': digest, 'k': ['2026-10-16T09:30:01+00:00', 'user_roles', 7]},
                  {'v': 2, 'f': digest, 'k': ['soon', 'user_roles', 7]},
                  {'v': 2, 'f': 'é' * 32, 'k': [stamp, 'user_roles', 7]},
                  {'v': 2, 'f': digest, 'k': [stamp, 'user_roles']}, [stamp, 'user_roles', 7]):
        assert detail(lambda state=state: audit.listing(filters, audit.signer.dumps(state))) == RELOAD
    assert audit.listing(filters, audit.signer.dumps({'v': 2, 'f': digest, 'k': [stamp, 'user_roles', 2**40]}))
    old = int(time.time()) - governance_audit.CURSOR_MAX_AGE - 5
    with monkeypatch.context() as patch:
        patch.setattr(TimestampSigner, 'get_timestamp', lambda self: old)
        expired = audit.listing(filters, None, 3)['next_cursor']
    assert detail(lambda: audit.listing(filters, expired)) == RELOAD


def test_csv_export_neutralizes_spreadsheet_formulas(store, audit):
    hostile = ['=HYPERLINK("https://evil.example","x")', '+1+1', '-2+3', '@SUM(A1)', '\tcmd', '\rcmd']
    for index, value in enumerate(hostile):
        governance_row(store, BASE + timedelta(seconds=index), actor=value, resource_id=value,
                       details={'note': value})
    governance_row(store, BASE + timedelta(minutes=1), actor='plain@example.com', resource_id='a,b "quoted"\nline')
    rows = list(csv.reader(io.StringIO(''.join(audit.export(None, 'csv')), newline='')))
    assert rows[0] == list(EXPORT_COLUMNS)
    assert rows[1][3:6] == ['plain@example.com', 'role', 'a,b "quoted"\nline']
    assert [(row[3], row[5]) for row in rows[2:]] == [("'" + value, "'" + value) for value in reversed(hostile)]
    assert [json.loads(row[6]) for row in rows[2:]] == [{'note': value} for value in reversed(hostile)]
    assert all(row[1] == 'governance' and row[2] == 'role.created' and row[4] == 'role' for row in rows[1:])
    assert all(not cell.startswith(governance_audit.FORMULA_PREFIXES) for row in rows for cell in row)
    # Activity cells take the same escaping.
    activity_row(store, BASE + timedelta(minutes=2), actor=hostile[0], session_id='+1')
    rows = list(csv.reader(io.StringIO(''.join(audit.export(None, 'csv')), newline='')))
    assert rows[1][1] == 'activity' and rows[1][3] == "'" + hostile[0]
    assert all(not cell.startswith(governance_audit.FORMULA_PREFIXES) for row in rows for cell in row)


def test_ndjson_and_csv_exports_follow_feed_order_in_pages_and_are_capped(store, audit, monkeypatch):
    random.seed(7)
    writers = (governance_row, user_role_row, connection_row, credential_row)
    for index in range(41):
        writers[index % 4](store, BASE + timedelta(seconds=random.randint(0, 3), microseconds=random.choice((0, 5))))
    listing = audit.listing(None, None, 200)['entries']
    assert records(audit.export(None, 'ndjson')) == listing
    monkeypatch.setattr(governance_audit, 'EXPORT_PAGE', 4)
    assert records(audit.export(None, 'ndjson')) == listing
    monkeypatch.setattr(governance_audit, 'MAX_EXPORT_ROWS', 10)
    *exported, truncated = records(audit.export(None, 'ndjson'))
    assert exported == listing[:10] and truncated['action'] == 'export.truncated'
    rows = list(csv.reader(io.StringIO(''.join(audit.export(None, 'csv')), newline='')))
    assert len(rows) == 12 and [row[0] for row in rows[1:11]] == [entry['created_at'] for entry in listing[:10]]
    assert rows[11][1:3] == ['export', 'export.truncated']
    # Exactly the cap, with nothing older left: no truncation record.
    filters = parse_filters(resource_type='credential')
    assert [entry['source'] for entry in records(audit.export(filters, 'ndjson'))] == ['credentials'] * 10


def test_capped_exports_end_with_a_record_that_resumes_without_skipping_rows(store, audit, monkeypatch):
    """Regression: a capped export ended like a complete one, so a collector moving its window on lost the oldest rows."""
    for second in (0, 1, 2, 3, 4, 6, 7, 8, 9):
        governance_row(store, BASE + timedelta(seconds=second))
    tie = BASE + timedelta(seconds=5)
    for _ in range(2):  # The cap cuts between rows of two sources at one instant.
        activity_row(store, tie)
        governance_row(store, tie)
    complete = [(entry['source'], entry['id']) for entry in audit.listing(None, None, 200)['entries']]
    window = parse_filters(after=BASE.isoformat(), before=(BASE + timedelta(minutes=1)).isoformat())
    monkeypatch.setattr(governance_audit, 'MAX_EXPORT_ROWS', 6)
    received, filters, markers = [], window, []
    while True:  # The documented collector loop.
        *entries, last = records(audit.export(filters, 'ndjson'))
        if last['source'] != 'export':
            received.extend([*entries, last])
            break
        received.extend(entries)
        markers.append(last)
        # CSV ends with the same record as its last row.
        rows = list(csv.reader(io.StringIO(''.join(audit.export(filters, 'csv')), newline='')))
        assert rows[-1] == [last['created_at'], 'export', 'export.truncated', '', 'export', '',
                            json.dumps(last['details'], sort_keys=True, separators=(',', ':'))]
        filters = parse_filters(after=window.after, before=last['details']['next_before'])
    assert [marker['details'] for marker in markers] == [
        {'rows': 6, 'next_before': (tie + timedelta(microseconds=1)).isoformat(timespec='microseconds')},
        {'rows': 6, 'next_before': (BASE + timedelta(seconds=3, microseconds=1)).isoformat(timespec='microseconds')}]
    assert list(dict.fromkeys((entry['source'], entry['id']) for entry in received)) == complete


def test_export_validates_before_streaming(audit, monkeypatch):
    assert detail(lambda: audit.export(None, 'xlsx')) == 'Choose csv or ndjson.'
    calls = []
    monkeypatch.setattr(GovernanceAudit, '_page', lambda self, *args: calls.append(args) or ([], None))
    stream = audit.export(None, 'csv')
    assert len(calls) == 1 and list(stream) == [','.join(EXPORT_COLUMNS) + '\r\n']


def test_facets_list_known_and_recorded_actions(store, audit):
    for action in ('scim_user.deactivated', 'role.created', 'role.created', 'spend_limit.updated'):
        governance_row(store, BASE, action=action)
    facets = audit.listing(None)['facets']
    assert facets == {'actions': sorted({*LEGACY_ACTIONS, *ACTIVITY_ACTIONS, 'scim_user.deactivated', 'role.created',
                                         'spend_limit.updated'}), 'resource_types': list(RESOURCE_TYPES)}
    assert {'session', 'message', 'policy', 'automation', 'sign_in', 'identity_binding'} <= set(facets['resource_types'])
    assert {'user_role.changed', 'connection.connected', 'credential.revoked'} <= set(facets['actions'])


def test_reads_never_take_the_writer_lock(store, audit, monkeypatch):
    for second in range(5):
        governance_row(store, BASE + timedelta(seconds=second))
        connection_row(store, BASE + timedelta(seconds=second))
    reads = []

    def forbidden(self):
        raise AssertionError('Audit reads must not take the writer lock.')

    for kind in (SQLiteConnection, PostgresConnection):
        original = kind.begin_read
        monkeypatch.setattr(kind, 'begin_write', forbidden)
        monkeypatch.setattr(kind, 'begin_read', lambda self, original=original: reads.append(1) or original(self))
    monkeypatch.setattr(governance_audit, 'EXPORT_PAGE', 3)
    assert len(pages(audit, limit=3)) == 10 and ''.join(audit.export(None, 'csv')).count('\r\n') == 11
    assert len(reads) == 4 + 4


def test_listing_proceeds_while_another_writer_holds_the_lock(store, audit):
    governance_row(store, BASE)
    if store.database:
        import psycopg
        holder = psycopg.connect(os.environ['MOYAI_TEST_POSTGRES_URL'])
        holder.execute('SELECT pg_advisory_xact_lock(726941, %s::regnamespace::oid::int)', (store.database.schema,))
        release = holder.rollback
    else:
        holder = sqlite3.connect(store.path, isolation_level=None)
        holder.execute('BEGIN IMMEDIATE')
        holder.execute("INSERT INTO connection_audit(provider,action,actor,created_at) VALUES('github','Paused','x','z')")
        release = holder.rollback
    try:
        with ThreadPoolExecutor(2) as pool:
            writer = pool.submit(user_role_row, store, BASE)
            time.sleep(0.3)
            assert not writer.done(), 'The lock holder must block ordinary writers.'
            started = time.monotonic()
            page = pool.submit(audit.listing, None).result(timeout=5)
            assert time.monotonic() - started < 5
            assert [entry['source'] for entry in page['entries']] == ['governance']
            exported = pool.submit(lambda: list(audit.export(None, 'ndjson'))).result(timeout=5)
            assert len(exported) == 1
            release()
            writer.result(timeout=10)
    finally:
        holder.close()
    assert [entry['source'] for entry in audit.listing(None)['entries']] == ['governance', 'user_roles']


def test_listing_reads_one_snapshot_while_writes_commit(store, audit, monkeypatch):
    for second in range(4):
        governance_row(store, BASE + timedelta(seconds=second))
        user_role_row(store, BASE + timedelta(seconds=second))
    original, inserted = governance_audit._Source.statement, threading.Event()

    def statement(self, *args):
        if self.name == 'governance' and not inserted.is_set():
            # A concurrent commit between two source reads of one page.
            inserted.set()
            with ThreadPoolExecutor(1) as pool:
                pool.submit(user_role_row, store, BASE + timedelta(hours=1)).result(timeout=10)
        return original(self, *args)

    monkeypatch.setattr(governance_audit._Source, 'statement', statement)
    page = audit.listing(None, None, 50)
    # One snapshot (REPEATABLE READ on PostgreSQL, a WAL read on SQLite) ignores the later commit.
    assert inserted.is_set() and len(page['entries']) == 8
    assert all(entry['created_at'] < '2026-10-16T10' for entry in page['entries'])
    assert len(audit.listing(None)['entries']) == 9


def test_feed_order_is_byte_order_whatever_the_database_collation(store, audit):
    """Regression: ICU sorts '.' before '+', so whole-second legacy rows sorted after fractional ones,
    paging skipped rows and the UI's whole-day bounds dropped events of the first second."""
    if not store.database:
        pytest.skip('SQLite compares text with BINARY, which is byte order.')
    if not store.rows("SELECT 1 FROM pg_collation WHERE collname='und-x-icu'"):
        pytest.skip('This PostgreSQL build has no ICU collations.')
    with store.connect() as conn:
        # An ICU database default reaches every column; columns are the closest disposable equivalent.
        for table in ('governance_audit_events', 'user_role_audit', 'connection_audit', 'credential_audit'):
            conn.execute(f'ALTER TABLE {table} ALTER COLUMN created_at TYPE TEXT COLLATE "und-x-icu"')
        conn.execute('ALTER TABLE governance_audit_events ALTER COLUMN id TYPE TEXT COLLATE "und-x-icu"')
    assert store.rows('''SELECT '2026-10-16T09:30:00+00:00' > '2026-10-16T09:30:00.500000+00:00' COLLATE "und-x-icu"
        AS reordered''') == [{'reordered': True}]
    user_role_row(store, BASE)
    user_role_row(store, BASE + timedelta(microseconds=500000))
    assert pages(audit, limit=1) == oracle(store) and len(oracle(store)) == 2
    start = BASE.replace(hour=0, minute=0)
    first_second = governance_row(store, start + timedelta(microseconds=250000))
    day = parse_filters(after='2026-10-16T00:00:00Z', before='2026-10-17T00:00:00Z')
    assert [entry['id'] for entry in audit.listing(day)['entries']][-1] == first_second
    random.seed(23)
    writers = (governance_row, user_role_row, connection_row, credential_row)
    for index in range(80):
        writers[index % 4](store, BASE + timedelta(seconds=random.randint(0, 3), microseconds=random.choice((0, 0, 1, 999999))))
    assert pages(audit, limit=1) == pages(audit, limit=7) == oracle(store)
    assert [entry['id'] for entry in records(audit.export(None, 'ndjson'))] == [ident for _, ident in oracle(store)]


def test_postgres_feed_pages_use_the_byte_ordered_indexes(store):
    if not store.database:
        pytest.skip('PostgreSQL plans only.')
    for action in ('scim_user.created', 'security_profile.created', 'security_profile.updated'):
        governance_row(store, BASE, action=action, resource_type=action.partition('.')[0])
    expected = {'activity': 'idx_activity_audit_time', 'connections': 'idx_connection_audit_time',
                'credentials': 'idx_credential_audit_time', 'governance': 'idx_governance_audit_time',
                'user_roles': 'idx_user_role_audit_time'}
    position = (BASE, 'governance', 'a' * 32)
    with store.connect() as conn:
        conn.execute('SET LOCAL enable_seqscan = off')
        conn.execute('SET LOCAL enable_sort = off')
        for source in governance_audit._POSTGRES_SOURCES:
            for filters, index in ((AuditFilters(), expected[source.name]),
                                   (parse_filters(after='2026-10-16T00:00:00Z'), expected[source.name]),
                                   (parse_filters(action='role.created'), 'idx_governance_audit_action'),
                                   # No index covers resource_type: one statement per security_profile.* action.
                                   (parse_filters(resource_type='security_profile'), 'idx_governance_audit_action')):
                statements = governance_audit._statements_in(conn, source, filters, position, 51)
                if source.name == 'governance':
                    assert len(statements) == (2 if filters.resource_type else 1)
                for statement in statements:
                    plan = '\n'.join(row[0] for row in conn.execute('EXPLAIN ' + statement[0],
                                                                    statement[1]).fetchall())
                    assert index in plan and 'Sort' not in plan.replace('Sort Key', ''), (source.name, plan)


def test_resource_type_filters_page_through_each_of_its_actions(store, audit, monkeypatch):
    """Regression: no index covers resource_type, so a filtered page walked every governance row."""
    random.seed(24)
    wanted = set()
    for index in range(90):
        instant = BASE + timedelta(seconds=random.randint(0, 4), microseconds=random.choice((0, 1, 999999)))
        if index % 6 == 0:
            action = random.choice(('security_profile.created', 'security_profile.updated',
                                    'security_profile.disabled'))
            wanted.add(('governance', governance_row(store, instant, action=action,
                                                     resource_type='security_profile')))
        else:
            governance_row(store, instant, action=random.choice(('scim_user.created', 'scim_user.updated')),
                           resource_type='scim_user')
        if index % 9 == 0:
            user_role_row(store, instant)
    # resource_type stays a recheck on a row whose action names another type.
    governance_row(store, BASE, action='security_profile.updated', resource_type='role')
    expected = [key for key in oracle(store) if key in wanted]
    filters = parse_filters(resource_type='security_profile')
    assert len(expected) == 15
    calls, original = [], governance_audit._Source.statement

    def statement(self, filters, *args):
        calls.append((self.name, filters.action))
        return original(self, filters, *args)

    with monkeypatch.context() as patch:
        patch.setattr(governance_audit._Source, 'statement', statement)
        assert pages(audit, filters, limit=1) == pages(audit, filters, limit=7) == expected
    assert {action for name, action in calls if name == 'governance'} == {
        'security_profile.created', 'security_profile.disabled', 'security_profile.updated'}
    assert [(entry['source'], entry['id']) for entry in records(audit.export(filters, 'ndjson'))] == expected
    assert pages(audit, parse_filters(resource_type='spend_limit')) == []
    # Older layouts' types name their actions differently, so they keep one unsplit statement.
    legacy = governance_row(store, BASE, action='security.defaults.updated', resource_type='SecurityDefaults')
    assert pages(audit, parse_filters(resource_type='SecurityDefaults')) == [('governance', legacy)]
    # At the action cap some actions may be unseen, so one unsplit statement reads them all.
    monkeypatch.setattr(governance_audit, 'MAX_FACET_ACTIONS', 2)
    assert pages(audit, filters, limit=1) == pages(audit, filters, limit=7) == expected


def test_recorded_actions_name_their_resource_type(store, audit):
    """Regression: a mismatched action committed, then vanished from resource_type-filtered pages and exports."""
    with store.connect() as conn:
        conn.begin_write()
        for action, resource_type in (('profile.updated', 'security_profile'), ('role_assignment.updated', 'role')):
            with pytest.raises(ValueError, match=r'^Name governance actions <resource_type>\.<verb>\.$'):
                record_event_in(conn, action, 'owner@example.com', resource_type, 'profile')
    assert store.rows('SELECT * FROM governance_audit_events') == []
    with store.connect() as conn:
        conn.begin_write()
        kept = record_event_in(conn, 'security_profile.updated', 'owner@example.com', 'security_profile', 'profile')
        # Types outside RESOURCE_TYPES keep their own names; the filter reads them unsplit.
        older = record_event_in(conn, 'role.updated', 'owner@example.com', 'CustomRole', 'auditor')
    assert pages(audit, parse_filters(resource_type='security_profile')) == [('governance', kept)]
    assert pages(audit, parse_filters(resource_type='CustomRole')) == [('governance', older)]
    # Native AI guardrail refusals insert event_values rows from their own transaction.
    action, actor, resource_type, resource_id, details = event_values(
        'ai_guardrail.violation', 'owner@example.com', 'ai_guardrail', 'phi-presidio',
        {'session_id': 'session', 'model': 'route-alias', 'guardrails': ['phi-presidio']})
    guardrail = governance_row(store, BASE, action=action, actor=actor, resource_type=resource_type,
                               resource_id=resource_id, details=json.loads(details))
    assert pages(audit, parse_filters(resource_type='ai_guardrail')) == [('governance', guardrail)]
    assert 'ai_guardrail' in audit.listing()['facets']['resource_types']


def test_activity_only_types_never_read_the_governance_table(store):
    """Session, message and policy rows live only in the activity table, so their filters skip the action scan."""
    for kind in ('session', 'message', 'policy'):
        with pytest.raises(ValueError, match=r'^Record session, message and policy activity in the activity audit\.$'):
            event_values(kind + '.created', 'owner@example.com', kind, 'x')
    governance_row(store, BASE, action='automation.created', resource_type='automation', resource_id='a' * 32)
    source = next(source for source in governance_audit._SOURCES if source.name == 'governance')

    class Counted:
        def __init__(self, conn):
            self.conn, self.scans = conn, 0

        def execute(self, sql, *args):
            self.scans += sql == governance_audit._ACTION_SCAN
            return self.conn.execute(sql, *args)

    with store.connect() as conn:
        counted = Counted(conn)
        for kind in ('session', 'message', 'policy'):
            for filters in (parse_filters(resource_type=kind), parse_filters(resource_type=kind, action=kind + '.x')):
                assert governance_audit._statements_in(counted, source, filters, None, 51) == []
        assert counted.scans == 0
        # Automation configuration changes are governance events: their filter still reads the table.
        automation = parse_filters(resource_type='automation')
        assert len(governance_audit._statements_in(counted, source, automation, None, 51)) == 1
        assert counted.scans == 1


def test_exports_release_one_chunk_per_page(store, audit, monkeypatch):
    """Regression: every row was its own chunk, so the route rechecked live authority and hopped threads per row."""
    for second in range(10):
        governance_row(store, BASE + timedelta(seconds=second))
    monkeypatch.setattr(governance_audit, 'EXPORT_PAGE', 4)
    chunks = list(audit.export(None, 'ndjson'))
    assert [chunk.count('\n') for chunk in chunks] == [4, 4, 2]
    assert records(chunks) == audit.listing(None, None, 200)['entries']
    chunks = list(audit.export(None, 'csv'))
    assert [chunk.count('\r\n') for chunk in chunks] == [5, 4, 2]
    assert chunks[0].startswith(','.join(EXPORT_COLUMNS) + '\r\n')


def test_facets_come_only_with_the_first_page(store, audit):
    """Regression: every load-more page recomputed facets that the client discards."""
    for second in range(3):
        governance_row(store, BASE + timedelta(seconds=second))
    first = audit.listing(None, None, 2)
    assert first['facets']['actions'] and first['next_cursor']
    assert audit.listing(None, first['next_cursor'], 2)['facets'] is None


def test_activity_rows_join_the_feed_filters_and_exports(store, audit):
    session = 'c' * 32
    created = activity_row(store, BASE, session_id=session, key=(session,))
    denied = activity_row(store, BASE + timedelta(seconds=1), 'policy.tool_denied', session_id=session)
    message = activity_row(store, BASE + timedelta(seconds=2), 'message.submitted', actor='Dana@Example.com',
                           actor_id='google:dana', resource_id='t' * 32, session_id=session)
    blocked = activity_row(store, BASE + timedelta(seconds=3), 'automation.blocked', resource_id='a' * 32,
                           session_id='', details={'occurrence_kind': 'schedule', 'reason': 'governance'})
    configured = governance_row(store, BASE + timedelta(seconds=4), action='automation.created',
                                resource_type='automation', resource_id='a' * 32, actor='owner@example.com',
                                details={'revision': 1, 'via': 'http'})
    # A retried write of a deduplicated event adds nothing.
    assert activity_row(store, BASE + timedelta(minutes=1), session_id=session, key=(session,)) == created
    entries = {entry['id']: entry for entry in audit.listing(None)['entries']}
    assert len(entries) == 5
    assert entries[created] == {
        'id': created, 'source': 'activity', 'action': 'session.created', 'actor': 'Owner@Example.com',
        'resource_type': 'session', 'resource_id': session,
        'details': {'origin': 'user', 'visibility': 'shared', 'profile_revision': 0, 'inherited': False,
                    'outcome': 'success', 'session_id': session},
        'created_at': fixed(BASE)}
    assert entries[denied]['details'] == {'reason': 'tool_disabled', 'tool': 'shell', 'outcome': 'denied',
                                          'session_id': session}
    assert entries[blocked]['details'] == {'occurrence_kind': 'schedule', 'reason': 'governance', 'outcome': 'denied'}

    # The folded actor_key serves a case-insensitive actor filter.
    assert pages(audit, parse_filters(actor=' OWNER@example.com ')) == [
        ('governance', configured), ('activity', blocked), ('activity', denied), ('activity', created)]
    assert pages(audit, parse_filters(actor='dana@example.com')) == [('activity', message)]
    assert pages(audit, parse_filters(resource_type='policy')) == [('activity', denied)]
    assert pages(audit, parse_filters(resource_type='session')) == [('activity', created)]
    assert pages(audit, parse_filters(resource_type='automation')) == [('governance', configured), ('activity', blocked)]
    assert pages(audit, parse_filters(action='message.submitted')) == [('activity', message)]
    assert pages(audit, parse_filters(action='automation.created')) == [('governance', configured)]
    assert pages(audit, parse_filters(resource_type='message', action='session.created')) == []
    rows = records(audit.export(parse_filters(resource_type='policy'), 'ndjson'))
    assert [(row['source'], row['details']['outcome']) for row in rows] == [('activity', 'denied')]
    assert 'session_id' in rows[0]['details']


def test_cursors_issued_before_activity_rows_stay_valid(store, audit):
    for second in range(6):
        governance_row(store, BASE + timedelta(seconds=second))
    first = audit.listing(None, None, 3)
    # Activity committed later, on both sides of the cursor.
    activity_row(store, BASE + timedelta(seconds=1))
    activity_row(store, BASE + timedelta(minutes=1))
    rest = audit.listing(None, first['next_cursor'], 50)['entries']
    assert [entry['source'] for entry in rest] == ['governance', 'activity', 'governance', 'governance']
    digest, stamp = AuditFilters().digest(), fixed(BASE)
    assert audit.listing(None, audit.signer.dumps({'v': 2, 'f': digest, 'k': [stamp, 'activity', 'a' * 32]}))
    for ident in (7, '', 'a' * 513, None):
        forged = audit.signer.dumps({'v': 2, 'f': digest, 'k': [stamp, 'activity', ident]})
        assert detail(lambda forged=forged: audit.listing(None, forged)) == RELOAD


def test_postgres_activity_filters_use_their_indexes(store):
    if not store.database:
        pytest.skip('PostgreSQL plans only.')
    for second in range(3):
        activity_row(store, BASE + timedelta(seconds=second))
        activity_row(store, BASE + timedelta(seconds=second), 'policy.tool_denied')
    source = next(source for source in governance_audit._POSTGRES_SOURCES if source.name == 'activity')
    position = (BASE, 'governance', 'a' * 32)
    with store.connect() as conn:
        conn.execute('SET LOCAL enable_seqscan = off')
        conn.execute('SET LOCAL enable_sort = off')
        for filters, index in ((AuditFilters(), 'idx_activity_audit_time'),
                               (parse_filters(actor='Owner@Example.com'), 'idx_activity_audit_actor'),
                               (parse_filters(action='policy.tool_denied'), 'idx_activity_audit_action'),
                               (parse_filters(resource_type='session'), 'idx_activity_audit_resource')):
            for cursor in (None, position):
                [statement] = governance_audit._statements_in(conn, source, filters, cursor, 51)
                assert 'unicode_lower' not in statement[0]  # The actor filter compares actor_key itself.
                plan = '\n'.join(row[0] for row in conn.execute('EXPLAIN ' + statement[0], statement[1]).fetchall())
                assert index in plan and 'Sort' not in plan.replace('Sort Key', ''), (filters, plan)
        # Governance-only filters never read the activity table.
        for filters in (parse_filters(action='role.created'), parse_filters(resource_type='sign_in')):
            assert governance_audit._statements_in(conn, source, filters, None, 51) == []
