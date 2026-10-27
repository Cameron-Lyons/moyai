"""Monthly USD model spend limits for the organization, each user and each session.

Rows: 'organization' caps the organization's month-to-date total, 'user-default'
caps each person's month-to-date total, 'session-default' caps each session's
lifetime total and 'user:<normalized email>' overrides the default for one
person (a NULL override means no limit for that person even when a default
applies). 'group:<SCIM group id>' tiers live in spend_group_limits: a tier
replaces the default for the live, active members of a live directory group.
A person's monthly limit is their override if present, else the most permissive
of their tiers (NULL, unlimited, beats any amount; then the highest), else the
default. Membership comes from SCIM, so whoever controls the identity provider's
groups controls which tier applies. Months are UTC calendar months. A NULL limit
is unlimited, 0 blocks every model request, and any other limit is a positive
amount of at most MAX_LIMIT_USD with at most two decimal places (the API
contract's bound).

Usage lives in the native inference ledger, so this module stores configuration
only. limits_from_rows(), evaluate(), refusal() and level() are pure, so
admission can read limits and usage in its own snapshot; resolve_in() reads one
person's limits, tiers included, in one statement. A refusal is a
SpendLimitReached with a fixed sentence per reason and no amounts, since sessions
can be shared. Writers take the canonical exclusive writer lock and record one
governance audit event per changed row in the same transaction. Routes enforce
spend.read and spend.manage, and SpendLimits(store, roles=...) rechecks
spend.manage inside each writer; a delegated spend manager cannot change the
tier of a group they belong to. Actors are GovernanceActor values (or anything
enterprise_roles.actor_label accepts); the label is the same text the other
governance writers record: the email, the shared sign-in name, or the id.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Annotated, Literal, LiteralString

from fastapi import HTTPException
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic_core import PydanticCustomError

from .enterprise_roles import GROUP_ID, STALE, GovernanceForbidden, actor_label, directory_groups_in, validated
from .governance_audit import initialize_schema as initialize_audit
from .governance_audit import record_event_in, timestamp
from .schema_initializers import initialize_scim
from .schema_initializers import initialize_spend_limits as initialize_schema

SINGLETONS = ('organization', 'user-default', 'session-default')
SCOPES = ('organization', 'user', 'session')  # evaluate() reports exceeded scopes in this order.
MAX_LIMIT_USD = 1_000_000
MAX_CHANGES = 50
MAX_USER_LIMITS = 10_000
MAX_GROUP_LIMITS = 1000
# level() warns once usage reaches this share of a limit.
WARNING_RATIO = Fraction(2, 3)
_INVALID_ID: LiteralString = ('Use organization, user-default, session-default, user:<work email> '
                              'or group:<directory group ID>.')
_RANGE: LiteralString = 'Use a limit from 0 to 1,000,000 USD.'  # Keep in step with MAX_LIMIT_USD.
_EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+")  # Same shape as app.user_roles.


class SpendLimitError(HTTPException):
    """A refused spend-limit operation. The detail is one fixed sentence."""
    status = 409
    message = 'This spend limit change was refused.'

    def __init__(self, detail: str | None = None):
        super().__init__(self.status, detail or self.message)


class StaleRevision(SpendLimitError):
    message = STALE


class SpendLimitNotFound(SpendLimitError):
    status, message = 404, 'Spend limit not found.'


class InvalidSpendLimit(SpendLimitError):
    status, message = 422, _INVALID_ID


class SpendLimitCapacity(SpendLimitError):
    message = f'At most {MAX_USER_LIMITS} per-person spend limits are supported.'


OWN_TIER = 'You cannot change the spend tier for a group you belong to.'
# Fixed refusals, one per reason. Each names the spend limit and none holds an
# amount, because a session and its failure messages can be shared.
REACHED = {
    'organization': "The organization's monthly model spend limit has been reached. Ask a spend manager to review it.",
    'user': ('Your monthly model spend limit has been reached. It resets on the first day of next month (UTC); '
             'ask a spend manager to raise it.'),
    'session': ('This session has reached its model spend limit. Start a new session or ask a spend manager to '
                'raise the per-session limit.'),
    'pending': ("A spend limit applies and an earlier model request's cost is still being recorded. "
                'Try again in a few minutes.'),
}


class SpendLimitReached(HTTPException):
    """A spend limit refused a paid model request: reason is a REACHED key and the detail its sentence."""

    def __init__(self, reason: str):
        if reason not in REACHED:
            raise ValueError('Unknown spend limit reason.')
        self.reason = reason
        super().__init__(403, REACHED[reason])


def normalize_email(value) -> str:
    """The canonical lowercase email, or '' when the value is not a work email."""
    if not isinstance(value, str):
        return ''
    value = value.strip().lower()
    return value if len(value) <= 254 and _EMAIL.fullmatch(value) else ''


def parse_id(value) -> tuple[str, str, str]:
    """(id, kind, subject) for a limit id; user and group ids are normalized. Raises InvalidSpendLimit."""
    if isinstance(value, str):
        value = value.strip()
        if value in SINGLETONS:
            return value, value, ''
        if value.startswith('user:') and (email := normalize_email(value[5:])):
            return 'user:' + email, 'user', email
        if value.startswith('group:') and GROUP_ID.fullmatch(group := value[6:].strip().lower()):
            return 'group:' + group, 'group', group
    raise InvalidSpendLimit()


def limit_ids(email) -> tuple[str, ...]:
    """The spend_limits rows resolve() reads for one person: the singletons and their override."""
    email = normalize_email(email)
    return SINGLETONS + (('user:' + email,) if email else ())


# One person's tiers, through live groups and their live, active SCIM user: the
# membership rules of enterprise_roles' group grants. Its one binding is the
# normalized email. Bare table names after single-spaced FROM/JOIN, so
# product_governance.CanonicalRead can qualify them; the admission statement
# appends it to the spend_limits read with UNION ALL.
GROUP_TIER_QUERY: LiteralString = (
    "SELECT 'group:' || l.group_id AS id, l.limit_usd AS limit_usd FROM spend_group_limits l "
    "JOIN scim_groups g ON g.id=l.group_id AND g.deleted_at='' "
    'JOIN scim_group_members m ON m.group_id=l.group_id '
    "JOIN scim_users u ON u.id=m.user_id AND u.deleted_at='' AND u.active=1 WHERE u.user_name=?")


def _change_id(value: str) -> str:
    try:
        return parse_id(value)[0]
    except InvalidSpendLimit:
        raise PydanticCustomError('spend_limit_id', _INVALID_ID) from None


def _amount(value: float | None) -> float | None:
    if value is None:
        return None
    if not 0 <= value <= MAX_LIMIT_USD:
        raise PydanticCustomError('spend_limit', _RANGE)
    exponent = Decimal(repr(float(value))).as_tuple().exponent
    if not isinstance(exponent, int) or exponent < -2:
        raise PydanticCustomError('spend_limit', 'Use at most two decimal places.')
    return float(value)


class SpendLimitChange(BaseModel):
    """One row change. limit_usd is required: null removes the limit, 0 blocks."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    id: Annotated[str, Field(min_length=1, max_length=260), AfterValidator(_change_id)]
    limit_usd: Annotated[Annotated[float, Field(strict=True, allow_inf_nan=False)] | None, AfterValidator(_amount)]
    revision: int = Field(ge=0, strict=True)


class SpendLimitChanges(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    changes: list[SpendLimitChange] = Field(min_length=1, max_length=MAX_CHANGES)


@dataclass(frozen=True, slots=True)
class SpendLimitSet:
    """Limits that apply to one request: None is unlimited and 0 blocks.

    organization and user are UTC calendar-month totals (user covers every actor
    id sharing the person's email); session is the session's lifetime total.
    user_source says where user came from; user_group is the tier's group id.
    """
    organization: float | None = None
    user: float | None = None
    session: float | None = None
    user_source: Literal['override', 'group', 'default'] = 'default'
    user_group: str = ''

    @property
    def unlimited(self) -> bool:
        return self.organization is None and self.user is None and self.session is None


def _corrupt(value) -> bool:
    return value is not None and (isinstance(value, bool) or not isinstance(value, (int, float, Decimal))
                                  or not _finite(value) or value < 0)


def _stored_limit(value):
    # A corrupt stored limit blocks rather than silently allowing spend.
    return 0.0 if _corrupt(value) else None if value is None else float(value)


def _most_permissive(tiers: Mapping[str, object]) -> tuple[str, float | None]:
    """(group id, limit) of the tier that applies; ties go to the lowest group id."""
    ordered = sorted(tiers.items())
    # A corrupt tier blocks: a higher tier must not silently outvote it.
    if corrupt := [group for group, value in ordered if _corrupt(value)]:
        return corrupt[0], 0.0
    if unlimited := [group for group, value in ordered if value is None]:
        return unlimited[0], None
    group, value = max(ordered, key=lambda item: float(item[1]))
    return group, float(value)


def limits_from_rows(rows: Iterable[Mapping], email) -> SpendLimitSet:
    """Resolve limits from the (id, limit_usd) rows resolve_in's statement returns.

    The person's override row, when present, replaces their tiers and
    user-default even when its limit is NULL. Otherwise their 'group:<id>' tier
    rows replace the default with the most permissive tier. An empty or invalid
    email can only use the default.
    """
    values, tiers = {}, {}
    for row in rows:
        if isinstance(row['id'], str) and row['id'].startswith('group:'):
            tiers[row['id'][6:]] = row['limit_usd']
        else:
            values[row['id']] = _stored_limit(row['limit_usd'])
    email = normalize_email(email)
    override = 'user:' + email if email else ''
    scopes = {'organization': values.get('organization'), 'session': values.get('session-default')}
    if override in values:
        return SpendLimitSet(**scopes, user=values[override], user_source='override')
    if email and tiers:
        group, limit = _most_permissive(tiers)
        return SpendLimitSet(**scopes, user=limit, user_source='group', user_group=group)
    return SpendLimitSet(**scopes, user=values.get('user-default'))


def _finite(value):
    return value.is_finite() if isinstance(value, Decimal) else math.isfinite(value)


def _decimal(value):
    # Limits have at most two decimals; compare their nominal value exactly with
    # Decimal ledger sums instead of the nearest binary float.
    return value if isinstance(value, Decimal) else Decimal(repr(value)) if isinstance(value, float) else Decimal(value)


def _reached(limit: float, used) -> bool:
    if used is not None and (isinstance(used, bool) or not isinstance(used, (int, float, Decimal))):
        raise TypeError('Spend usage amounts must be numbers.')
    return used is None or not _finite(used) or used < 0 or _decimal(used) >= _decimal(float(limit))


def evaluate(limits: SpendLimitSet, usage: Mapping[str, int | float | Decimal | None]) -> list[str]:
    """Scopes whose limit is reached, in SCOPES order: used >= limit (0 always blocks).

    usage maps 'organization', 'user' and 'session' to spend in USD. Scopes
    without a limit ignore usage, so callers may skip those sums. For a limited
    scope, missing, None, negative or non-finite usage counts as reached (fail
    closed); a non-numeric value raises TypeError.
    """
    if not isinstance(limits, SpendLimitSet) or not isinstance(usage, Mapping):
        raise TypeError('Evaluate a SpendLimitSet against a usage mapping.')
    return [scope for scope in SCOPES
            if (limit := getattr(limits, scope)) is not None and _reached(limit, usage.get(scope))]


def evaluation(limits: SpendLimitSet,
               usage: Mapping[str, int | float | Decimal | None]) -> tuple[list[str], list[str]]:
    """(exceeded, pending): evaluate()'s scopes, and those of them reached only because a cost is awaited.

    Admission reports usage awaiting a recoverable cost as None. A 0 limit is
    reached whatever the usage, so it is never pending.
    """
    exceeded = evaluate(limits, usage)
    return exceeded, [scope for scope in exceeded if usage.get(scope) is None and getattr(limits, scope) != 0]


def refusal(limits: SpendLimitSet, usage: Mapping[str, int | float | Decimal | None]) -> str | None:
    """The SpendLimitReached reason for this usage, or None when every limit admits a request.

    The first scope in SCOPES order that recorded spend reaches wins over one
    awaiting a cost, since waiting would not help.
    """
    exceeded, pending = evaluation(limits, usage)
    reached = [scope for scope in exceeded if scope not in pending]
    return reached[0] if reached else 'pending' if pending else None


def level(limit: float | None, used: int | float | Decimal | None) -> Literal['ok', 'warning', 'reached', 'pending']:
    """How close used is to limit, for notices only; admission uses evaluate().

    'reached' as evaluate() counts it (0 always), 'pending' while a cost is
    awaited (used None), 'warning' from WARNING_RATIO of the limit, else 'ok'.
    No limit is 'ok'.
    """
    if limit is None:
        return 'ok'
    if limit != 0 and used is None:
        return 'pending'
    if _reached(limit, used):
        return 'reached'
    return 'warning' if (_decimal(used) * WARNING_RATIO.denominator
                         >= _decimal(float(limit)) * WARNING_RATIO.numerator) else 'ok'


def group_name_in(conn, group_id: str) -> str:
    """A directory group's display name, deleted or not; '' when unknown or without an id."""
    row = conn.execute('SELECT display_name FROM scim_groups WHERE id=?', (group_id,)).fetchone() if group_id else None
    return row['display_name'] if row else ''


def _limit_usd(row) -> float | None:
    return None if row is None or row['limit_usd'] is None else float(row['limit_usd'])


def _location(identity: str, kind: str, subject: str) -> tuple[str, str, str]:
    """(table, key column, key) of a limit's row: tiers live in spend_group_limits by group id."""
    return ('spend_group_limits', 'group_id', subject) if kind == 'group' else ('spend_limits', 'id', identity)


def _view(row):
    return {'id': row['id'], 'kind': row['kind'], 'subject': row['subject'], 'limit_usd': _limit_usd(row),
            'revision': row['revision'], 'updated_at': row['updated_at'], 'updated_by': row['updated_by']}


def _absent(identity):
    return {'id': identity, 'kind': identity, 'subject': '', 'limit_usd': None, 'revision': 0,
            'updated_at': None, 'updated_by': ''}


def _tier_view(row, group_name: str):
    return {'id': 'group:' + row['group_id'], 'group_id': row['group_id'], 'group_name': group_name,
            'limit_usd': _limit_usd(row), 'revision': row['revision'], 'updated_at': row['updated_at'],
            'updated_by': row['updated_by']}


_COLUMNS = 'id,kind,subject,limit_usd,revision,updated_by,updated_at'
_TIER_COLUMNS = 'group_id,limit_usd,revision,updated_by,updated_at'


class SpendLimits:
    """Synchronous canonical service; async callers run it in a worker thread.

    roles: an EnterpriseRoles over the same store. When given, every write
    re-resolves the actor inside its writer transaction and requires
    spend.manage, as enterprise_roles does; the label is then the resolved
    authority's (the same text actor_label gives).
    """

    def __init__(self, store, *, roles=None):
        self.store, self.roles = store, roles
        if store.schema_updates:
            initialize_schema(store)
            initialize_scim(store)
            initialize_audit(store)

    def _authorized_in(self, conn, actor, label: str):
        """(label, authority): with roles, the actor re-resolved in this transaction, holding spend.manage."""
        if self.roles is None:
            return label, None
        authority = self.roles.authorize_in(conn, actor, 'spend.manage')
        return authority.label, authority

    @staticmethod
    def _refuse_own_group_in(conn, authority, group_id: str) -> None:
        """A delegated spend manager may not set the tier of a live group they belong to, as with group grants."""
        if authority is not None and authority.delegate and conn.execute(
                '''SELECT 1 FROM scim_group_members m JOIN scim_users u ON u.id=m.user_id
                JOIN scim_groups g ON g.id=m.group_id AND g.deleted_at=''
                WHERE m.group_id=? AND u.user_name=? AND u.deleted_at='' ''', (group_id, authority.email)).fetchone():
            raise GovernanceForbidden(OWN_TIER)

    @staticmethod
    def listing_in(conn) -> dict:
        """The three singletons (always present; revision 0 when never saved), then overrides by email.

        group_limits lists the tiers of live directory groups in the order of
        directory_groups (every live group, for choosing one).
        orphaned_group_limits lists the tiers of deleted groups by their last
        name: they never apply, but count toward MAX_GROUP_LIMITS until deleted.
        """
        rows = {row['id']: _view(row) for row in conn.execute(f'SELECT {_COLUMNS} FROM spend_limits')}
        users = sorted((row for row in rows.values() if row['kind'] == 'user'), key=lambda row: row['subject'])
        groups = directory_groups_in(conn)
        tiers = {row['group_id']: row for row in conn.execute(
            'SELECT l.group_id,l.limit_usd,l.revision,l.updated_by,l.updated_at,g.display_name '
            'FROM spend_group_limits l LEFT JOIN scim_groups g ON g.id=l.group_id')}
        live = {group['id'] for group in groups}
        orphaned = sorted((row for group_id, row in tiers.items() if group_id not in live),
                          key=lambda row: (row['display_name'] or '', row['group_id']))
        return {'limits': [rows.get(identity) or _absent(identity) for identity in SINGLETONS] + users,
                'group_limits': [{**_tier_view(tiers[group['id']], group['display_name']),
                                  'member_count': group['member_count']} for group in groups if group['id'] in tiers],
                'directory_groups': groups,
                'orphaned_group_limits': [_tier_view(row, row['display_name'] or '') for row in orphaned]}

    def listing(self) -> dict:
        with self.store.connect() as conn:
            conn.begin_read()
            return self.listing_in(conn)

    @staticmethod
    def resolve_in(conn, email) -> SpendLimitSet:
        """One person's limits from ONE statement: the singletons, their override and their tiers.

        Native admission runs it on every paid model request, so it must stay a
        single read with no writes.
        """
        email = normalize_email(email)
        ids = limit_ids(email)
        query = f"SELECT id,limit_usd FROM spend_limits WHERE id IN ({','.join('?' * len(ids))})"
        if email:
            query, ids = query + ' UNION ALL ' + GROUP_TIER_QUERY, (*ids, email)
        return limits_from_rows(conn.execute(query, ids), email)

    @staticmethod
    def effective_in(conn, email) -> dict:
        """The monthly limit that applies to one person and where it comes from (source and group)."""
        email = normalize_email(email)
        if not email:
            raise InvalidSpendLimit('Enter a work email address.')
        limits = SpendLimits.resolve_in(conn, email)
        return {'email': email, 'limit_usd': limits.user, 'source': limits.user_source,
                'group_id': limits.user_group, 'group_name': group_name_in(conn, limits.user_group)}

    def resolve(self, email) -> SpendLimitSet:
        with self.store.connect() as conn:
            conn.begin_read()
            return self.resolve_in(conn, email)

    @staticmethod
    def _first_revision_in(conn, identity) -> int:
        """1, or one past the highest revision a deleted override or tier of this id reached.

        Deleting an override or tier and creating it again must not restart at
        a revision an editor of the deleted row still holds, or that stale
        editor would overwrite the replacement. Deletes record their revision
        in the same transaction, through idx_governance_audit_action.
        """
        highest = 0
        for row in conn.execute("SELECT details FROM governance_audit_events WHERE action='spend_limit.deleted' "
                                'AND resource_id=?', (identity,)):
            try:
                value = json.loads(row['details']).get('revision')
            except (AttributeError, TypeError, ValueError):
                continue
            if type(value) is int:
                highest = max(highest, value)
        return highest + 1

    def _new_row_in(self, conn, identity: str, kind: str, counts: dict[str, int]) -> int:
        """Count one new override or tier against its capacity and return its first revision."""
        if kind not in counts:
            source = "spend_limits WHERE kind='user'" if kind == 'user' else 'spend_group_limits'
            counts[kind] = conn.execute(f'SELECT COUNT(*) AS total FROM {source}').fetchone()['total']
        if kind == 'user' and counts[kind] >= MAX_USER_LIMITS:
            raise SpendLimitCapacity()
        if kind == 'group' and counts[kind] >= MAX_GROUP_LIMITS:
            raise SpendLimitCapacity(f'At most {MAX_GROUP_LIMITS} directory group spend tiers are supported.')
        counts[kind] += 1
        return self._first_revision_in(conn, identity)

    def save(self, changes: SpendLimitChanges | Mapping | Sequence, actor) -> dict:
        """Apply 1-50 revisioned changes all-or-nothing and return the new listing.

        Revision 0 creates a row and fails as stale when it exists; a re-created
        override or tier continues after its deleted revision. Unchanged values
        (and NULL for a never-saved singleton) write nothing. A tier's group
        must be live (404 otherwise).
        """
        if isinstance(changes, Sequence) and not isinstance(changes, (str, bytes)):
            changes = {'changes': list(changes)}
        body, label = validated(SpendLimitChanges, changes), actor_label(actor)
        if len({change.id for change in body.changes}) != len(body.changes):
            raise InvalidSpendLimit('Change each spend limit once.')
        with self.store.connect() as conn:
            conn.begin_write()
            label, authority = self._authorized_in(conn, actor, label)
            stamp, counts = timestamp(), {}
            for change in body.changes:
                identity, kind, subject = parse_id(change.id)
                details = {'kind': kind}
                if kind == 'group':
                    group = conn.execute("SELECT display_name FROM scim_groups WHERE id=? AND deleted_at=''",
                                         (subject,)).fetchone()
                    if group is None:
                        raise SpendLimitNotFound('Directory group not found.')
                    self._refuse_own_group_in(conn, authority, subject)
                    details['group_name'] = group['display_name']
                table, key, value = _location(identity, kind, subject)
                row = conn.execute(f'SELECT limit_usd,revision FROM {table} WHERE {key}=?', (value,)).fetchone()
                if (row['revision'] if row else 0) != change.revision:
                    raise StaleRevision()
                previous = _limit_usd(row)
                # Overrides and tiers are created even without a limit: NULL means unlimited for them.
                if previous == change.limit_usd and (row is not None or kind in SINGLETONS):
                    continue
                if row is None:
                    revision = 1 if kind in SINGLETONS else self._new_row_in(conn, identity, kind, counts)
                    if kind == 'group':
                        conn.execute(f'INSERT INTO spend_group_limits({_TIER_COLUMNS}) VALUES(?,?,?,?,?)',
                                     (subject, change.limit_usd, revision, label, stamp))
                    else:
                        conn.execute(f'INSERT INTO spend_limits({_COLUMNS}) VALUES(?,?,?,?,?,?,?)',
                                     (identity, kind, subject, change.limit_usd, revision, label, stamp))
                    action = 'spend_limit.created'
                else:
                    revision = row['revision'] + 1
                    if conn.execute(f'''UPDATE {table} SET limit_usd=?,revision=?,updated_by=?,updated_at=?
                            WHERE {key}=? AND revision=?''', (change.limit_usd, revision, label, stamp, value,
                                                             row['revision'])).rowcount != 1:
                        raise StaleRevision()
                    action = 'spend_limit.updated'
                record_event_in(conn, action, label, 'spend_limit', identity, {
                    **details, 'limit_usd': change.limit_usd, 'previous_usd': previous, 'revision': revision})
            return self.listing_in(conn)

    def delete(self, limit_id: str, revision: int, actor) -> dict:
        """Remove one person's override or one group's tier (live or deleted), so the default applies again."""
        if type(revision) is not int:
            raise TypeError('Spend limit revisions are integers.')
        identity, kind, subject = parse_id(limit_id)
        if kind not in ('user', 'group'):
            raise InvalidSpendLimit('Only per-person overrides and group tiers can be deleted. '
                                    'Save no limit to clear this one.')
        label = actor_label(actor)
        with self.store.connect() as conn:
            conn.begin_write()
            label, authority = self._authorized_in(conn, actor, label)
            table, key, value = _location(identity, kind, subject)
            row = conn.execute(f'SELECT limit_usd,revision FROM {table} WHERE {key}=?', (value,)).fetchone()
            if row is None:
                raise SpendLimitNotFound()
            details = {'kind': kind, 'limit_usd': None, 'previous_usd': _limit_usd(row), 'revision': revision}
            if kind == 'group':
                self._refuse_own_group_in(conn, authority, subject)
                details['group_name'] = group_name_in(conn, subject)
            if row['revision'] != revision or conn.execute(
                    f'DELETE FROM {table} WHERE {key}=? AND revision=?', (value, revision)).rowcount != 1:
                raise StaleRevision()
            record_event_in(conn, 'spend_limit.deleted', label, 'spend_limit', identity, details)
        return {'id': identity, 'deleted': True}
