"""A committed, metadata-only governance feed with snapshot pagination.

Source audit rows are immutable. Their delivery index is filled under the existing
database writer lock, so concurrent commits cannot disappear behind a cursor.
Only identifiers, actions, authenticated actors and timestamps enter this index.
"""
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from itsdangerous import BadSignature, SignatureExpired

from .db import now


SOURCES = {
    'enterprise_role_audit': """SELECT 'role:' || CAST(id AS TEXT) AS source_key,action,actor,
        CASE WHEN action LIKE 'assignment.%' THEN 'UserRoleAssignment'
             WHEN action LIKE 'group-grant.%' THEN 'GroupRoleGrant' ELSE 'CustomRole' END AS resource_type,
        subject AS resource_id,created_at FROM enterprise_role_audit""",
    'user_role_audit': """SELECT 'user-role:' || CAST(id AS TEXT) AS source_key,
        'user.role.updated' AS action,actor,'UserRoleAssignment' AS resource_type,
        email AS resource_id,created_at FROM user_role_audit""",
    'scim_audit': """SELECT 'scim:' || id AS source_key,action,actor,resource_type,resource_id,created_at
        FROM scim_audit""",
    'security_profile_revisions': """SELECT 'profile:' || profile_id || ':' || CAST(revision AS TEXT) AS source_key,
        'security.profile.updated' AS action,created_by AS actor,'SecurityProfile' AS resource_type,
        profile_id AS resource_id,created_at FROM security_profile_revisions""",
    'governance_audit_events': """SELECT 'governance:' || id AS source_key,action,actor,resource_type,resource_id,created_at
        FROM governance_audit_events""",
}


FILTER_LENGTHS = {'actor': 254, 'action': 120, 'resource_type': 120, 'resource_id': 254, 'start': 64, 'end': 64}


def normalize_filters(**values):
    """Exact metadata filters and an inclusive/exclusive UTC timestamp interval."""
    filters = {}
    for key, maximum in FILTER_LENGTHS.items():
        value = values.get(key, '')
        if not isinstance(value, str) or len(value) > maximum:
            raise HTTPException(422, 'Invalid audit filter.')
        value = value.strip()
        if not value:
            continue
        if key in {'start', 'end'}:
            try:
                stamp = datetime.fromisoformat(value)
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    raise ValueError()
                value = stamp.astimezone(timezone.utc).isoformat()
            except (ValueError, OverflowError):
                raise HTTPException(422, 'Audit times must be ISO 8601 timestamps with a timezone.') from None
        filters[key] = value
    if 'start' in filters and 'end' in filters and datetime.fromisoformat(filters['start']) >= datetime.fromisoformat(filters['end']):
        raise HTTPException(422, 'The audit end time must be later than the start time.')
    return filters


def record_event_in(conn, action, actor, resource_type, resource_id):
    """Record metadata in the mutation's own transaction; never accept raw content."""
    identity = uuid4().hex
    conn.execute('''INSERT INTO governance_audit_events(id,action,actor,resource_type,resource_id,created_at)
        VALUES(?,?,?,?,?,?)''', (identity, action, actor, resource_type, resource_id, now()))
    return identity


class GovernanceAudit:
    def __init__(self, store, security):
        self.store, self.security = store, security
        if store.schema_updates:
            initialize_schema(store)

    def index_in(self, conn):
        tables = conn.table_names()
        sources = [query for table, query in SOURCES.items() if table in tables]
        if not sources:
            return
        # The exclusive transaction lock admits every prior source commit before
        # assigning deliveries. Source keys deduplicate repeated index passes.
        query = ' UNION ALL '.join(sources)
        conn.execute(f'''INSERT INTO governance_audit_index(source_key,action,actor,resource_type,resource_id,created_at)
            SELECT incoming.source_key,incoming.action,incoming.actor,incoming.resource_type,
                   incoming.resource_id,incoming.created_at FROM ({query}) AS incoming
            WHERE NOT EXISTS (SELECT 1 FROM governance_audit_index saved WHERE saved.source_key=incoming.source_key)
            ORDER BY incoming.created_at,incoming.source_key
            ON CONFLICT(source_key) DO NOTHING''')

    def cursor(self, cap, before, filters=None):
        return self.security.signer.dumps({'v': 2, 'cap': cap, 'before': before, 'filters': filters or {}},
                                          salt='governance-audit-v1')

    def read_cursor(self, value):
        try:
            state = self.security.signer.loads(value, salt='governance-audit-v1', max_age=86400)
            if (not isinstance(state, dict) or type(state.get('v')) is not int
                    or not (state['v'] == 1 and set(state) == {'v', 'cap', 'before'}
                            or state['v'] == 2 and set(state) == {'v', 'cap', 'before', 'filters'})
                    or type(state['cap']) is not int or type(state['before']) is not int
                    or state['cap'] < 0 or not 0 <= state['before'] <= state['cap'] + 1):
                raise ValueError()
            filters = state.get('filters', {})
            if (not isinstance(filters, dict) or not filters.keys() <= FILTER_LENGTHS.keys()
                    or normalize_filters(**filters) != filters):
                raise ValueError()
            state['filters'] = filters
            return state
        except (BadSignature, SignatureExpired, ValueError, TypeError, HTTPException):
            raise HTTPException(422, 'Invalid or expired audit cursor. Reload the audit history.') from None

    def listing(self, cursor='', limit=50, *, actor='', action='', resource_type='', resource_id='', start='', end=''):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HTTPException(422, 'Choose an audit page size from 1 to 100.')
        filters = normalize_filters(actor=actor, action=action, resource_type=resource_type,
                                    resource_id=resource_id, start=start, end=end)
        state = self.read_cursor(cursor) if cursor else None
        if state and state['filters'] != filters:
            raise HTTPException(422, 'Audit filters changed. Reload the audit history.')
        conditions, parameters = [], []
        for key, value in filters.items():
            column, comparison = ('created_at', '>=') if key == 'start' else ('created_at', '<') if key == 'end' else (key, '=')
            conditions.append(f'{column}{comparison}?')
            parameters.append(value)
        where = ''.join(' AND ' + condition for condition in conditions)
        with self.store.connect() as conn:
            if state:
                # A cursor's cap fixes its snapshot, so later index rows cannot enter
                # it; skip the writer lock and full source scan for earlier pages.
                conn.begin_read()
            else:
                conn.begin_write()
                self.index_in(conn)
            cap = state['cap'] if state else conn.execute(
                'SELECT coalesce(max(delivery),0) AS n FROM governance_audit_index').fetchone()['n']
            before = state['before'] if state else cap + 1
            rows = conn.execute(f'''SELECT delivery,source_key,action,actor,resource_type,resource_id,created_at
                FROM governance_audit_index WHERE delivery<=? AND delivery<?{where} ORDER BY delivery DESC LIMIT ?''',
                (cap, before, *parameters, limit + 1)).fetchall()
            selected = rows[:limit]
            next_cursor = self.cursor(cap, selected[-1]['delivery'], filters) if len(rows) > limit else None
            events = [{'id': row['source_key'], **{key: row[key] for key in
                      ('action', 'actor', 'resource_type', 'resource_id', 'created_at')}} for row in selected]
        return {'events': events, 'next_cursor': next_cursor}

    def routes(self):
        router = APIRouter()

        @router.get('/api/admin/governance/audit')
        def audit(request: Request, cursor: str = Query(default='', max_length=2048),
                  limit: int = Query(default=50, ge=1, le=100),
                  actor: str = Query(default='', max_length=254), action: str = Query(default='', max_length=120),
                  resource_type: str = Query(default='', max_length=120), resource_id: str = Query(default='', max_length=254),
                  start: str = Query(default='', max_length=64), end: str = Query(default='', max_length=64)):
            self.security.require(request, permission='audit.read')
            return self.listing(cursor, limit, actor=actor, action=action, resource_type=resource_type,
                                resource_id=resource_id, start=start, end=end)

        return router


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS governance_audit_events (
        id TEXT PRIMARY KEY,action TEXT NOT NULL,actor TEXT NOT NULL,resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,created_at TEXT NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS governance_audit_index (
        delivery INTEGER PRIMARY KEY AUTOINCREMENT,source_key TEXT NOT NULL UNIQUE,
        action TEXT NOT NULL,actor TEXT NOT NULL,resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,created_at TEXT NOT NULL)''')
