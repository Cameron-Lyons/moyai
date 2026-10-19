"""Monthly USD model spend limits for the organization, each user and each session.

Rows: 'organization' caps the organization's month-to-date total, 'user-default'
caps each person's month-to-date total, 'session-default' caps each session's
lifetime total and 'user:<normalized email>' overrides the default for one
person (a NULL override means no limit for that person even when a default
applies). Months are UTC calendar months. A NULL limit is unlimited, 0 blocks
every model request, and any other limit is a positive amount of at most
MAX_LIMIT_USD with at most two decimal places (the API contract's bound).

Usage lives in the native inference ledger, so this module stores configuration
only. limits_from_rows() and evaluate() are pure, so admission can read limits
and usage in its own snapshot. Writers take the canonical exclusive writer lock
and record one governance audit event per changed row in the same transaction.
Routes enforce spend.read and spend.manage, and SpendLimits(store, roles=...)
rechecks spend.manage inside each writer. Actors are GovernanceActor values (or
anything enterprise_roles.actor_label accepts); the label is the same text the
other governance writers record: the email, the shared sign-in name, or the id.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, LiteralString

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import PydanticCustomError

from .enterprise_roles import actor_label
from .governance_audit import initialize_schema as initialize_audit
from .governance_audit import record_event_in, timestamp
from .schema_initializers import initialize_spend_limits as initialize_schema

SINGLETONS = ('organization', 'user-default', 'session-default')
SCOPES = ('organization', 'user', 'session')  # evaluate() reports exceeded scopes in this order.
MAX_LIMIT_USD = 1_000_000
MAX_CHANGES = 50
MAX_USER_LIMITS = 10_000
STALE = 'This changed elsewhere. Reload and try again.'
_INVALID_ID: LiteralString = 'Use organization, user-default, session-default or user:<work email>.'
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


def normalize_email(value) -> str:
    """The canonical lowercase email, or '' when the value is not a work email."""
    if not isinstance(value, str):
        return ''
    value = value.strip().lower()
    return value if len(value) <= 254 and _EMAIL.fullmatch(value) else ''


def parse_id(value) -> tuple[str, str, str]:
    """(id, kind, subject) for a limit id; user ids are normalized. Raises InvalidSpendLimit."""
    if isinstance(value, str):
        value = value.strip()
        if value in SINGLETONS:
            return value, value, ''
        if value.startswith('user:') and (email := normalize_email(value[5:])):
            return 'user:' + email, 'user', email
    raise InvalidSpendLimit()


def limit_ids(email) -> tuple[str, ...]:
    """The rows resolve() reads for one person: the singletons and their override."""
    email = normalize_email(email)
    return SINGLETONS + (('user:' + email,) if email else ())


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
    """
    organization: float | None = None
    user: float | None = None
    session: float | None = None

    @property
    def unlimited(self) -> bool:
        return self.organization is None and self.user is None and self.session is None


def _stored_limit(value):
    if value is None:
        return None
    # A corrupt stored limit blocks rather than silently allowing spend.
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)) or not _finite(value) or value < 0:
        return 0.0
    return float(value)


def limits_from_rows(rows: Iterable[Mapping], email) -> SpendLimitSet:
    """Resolve limits from spend_limits rows (id, limit_usd) read by the caller.

    The person's override row, when present, replaces user-default even when
    its limit is NULL. An empty or invalid email can only use the default.
    """
    values = {row['id']: _stored_limit(row['limit_usd']) for row in rows}
    email = normalize_email(email)
    override = 'user:' + email if email else ''
    return SpendLimitSet(organization=values.get('organization'),
                         user=values[override] if override in values else values.get('user-default'),
                         session=values.get('session-default'))


def _finite(value):
    return value.is_finite() if isinstance(value, Decimal) else math.isfinite(value)


def _decimal(value):
    # Limits have at most two decimals; compare their nominal value exactly with
    # Decimal ledger sums instead of the nearest binary float.
    return value if isinstance(value, Decimal) else Decimal(repr(value)) if isinstance(value, float) else Decimal(value)


def evaluate(limits: SpendLimitSet, usage: Mapping[str, int | float | Decimal | None]) -> list[str]:
    """Scopes whose limit is reached, in SCOPES order: used >= limit (0 always blocks).

    usage maps 'organization', 'user' and 'session' to spend in USD. Scopes
    without a limit ignore usage, so callers may skip those sums. For a limited
    scope, missing, None, negative or non-finite usage counts as reached (fail
    closed); a non-numeric value raises TypeError.
    """
    if not isinstance(limits, SpendLimitSet) or not isinstance(usage, Mapping):
        raise TypeError('Evaluate a SpendLimitSet against a usage mapping.')
    exceeded = []
    for scope in SCOPES:
        limit = getattr(limits, scope)
        if limit is None:
            continue
        used = usage.get(scope)
        if used is not None and (isinstance(used, bool) or not isinstance(used, (int, float, Decimal))):
            raise TypeError('Spend usage amounts must be numbers.')
        if used is None or not _finite(used) or used < 0 or _decimal(used) >= _decimal(float(limit)):
            exceeded.append(scope)
    return exceeded


def validated[M: BaseModel](model: type[M], value) -> M:
    """Validate a library input like a request body: errors become a safe 422."""
    if isinstance(value, model):
        return value
    if isinstance(value, BaseModel):
        value = value.model_dump()
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise RequestValidationError(error.errors(include_url=False, include_input=False,
                                                  include_context=False)) from None


def _view(row):
    return {'id': row['id'], 'kind': row['kind'], 'subject': row['subject'],
            'limit_usd': None if row['limit_usd'] is None else float(row['limit_usd']),
            'revision': row['revision'], 'updated_at': row['updated_at'], 'updated_by': row['updated_by']}


def _absent(identity):
    return {'id': identity, 'kind': identity, 'subject': '', 'limit_usd': None, 'revision': 0,
            'updated_at': None, 'updated_by': ''}


_COLUMNS = 'id,kind,subject,limit_usd,revision,updated_by,updated_at'


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
            initialize_audit(store)

    def _authorized_in(self, conn, actor, label: str) -> str:
        return label if self.roles is None else self.roles.authorize_in(conn, actor, 'spend.manage').label

    @staticmethod
    def listing_in(conn) -> dict:
        """The three singletons (always present; revision 0 when never saved), then overrides by email."""
        rows = {row['id']: _view(row) for row in conn.execute(f'SELECT {_COLUMNS} FROM spend_limits')}
        users = sorted((row for row in rows.values() if row['kind'] == 'user'), key=lambda row: row['subject'])
        return {'limits': [rows.get(identity) or _absent(identity) for identity in SINGLETONS] + users}

    def listing(self) -> dict:
        with self.store.connect() as conn:
            conn.begin_read()
            return self.listing_in(conn)

    @staticmethod
    def resolve_in(conn, email) -> SpendLimitSet:
        ids = limit_ids(email)
        rows = conn.execute(f"SELECT id,limit_usd FROM spend_limits WHERE id IN ({','.join('?' * len(ids))})", ids)
        return limits_from_rows(rows, email)

    def resolve(self, email) -> SpendLimitSet:
        with self.store.connect() as conn:
            conn.begin_read()
            return self.resolve_in(conn, email)

    @staticmethod
    def _first_revision_in(conn, identity) -> int:
        """1, or one past the highest revision a deleted override of this id reached.

        Deleting an override and creating it again must not restart at a
        revision an editor of the deleted row still holds, or that stale editor
        would overwrite the replacement. Deletes record their revision in the
        same transaction, through idx_governance_audit_action.
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

    def save(self, changes: SpendLimitChanges | Mapping | Sequence, actor) -> dict:
        """Apply 1-50 revisioned changes all-or-nothing and return the new listing.

        Revision 0 creates a row and fails as stale when it exists; a re-created
        override continues after its deleted revision. Unchanged values (and
        NULL for a never-saved singleton) write nothing.
        """
        if isinstance(changes, Sequence) and not isinstance(changes, (str, bytes)):
            changes = {'changes': list(changes)}
        body, label = validated(SpendLimitChanges, changes), actor_label(actor)
        if len({change.id for change in body.changes}) != len(body.changes):
            raise InvalidSpendLimit('Change each spend limit once.')
        with self.store.connect() as conn:
            conn.begin_write()
            label = self._authorized_in(conn, actor, label)
            stamp, users = timestamp(), None
            for change in body.changes:
                identity, kind, subject = parse_id(change.id)
                row = conn.execute(f'SELECT {_COLUMNS} FROM spend_limits WHERE id=?', (identity,)).fetchone()
                if (row['revision'] if row else 0) != change.revision:
                    raise StaleRevision()
                previous = None if row is None or row['limit_usd'] is None else float(row['limit_usd'])
                if previous == change.limit_usd and (row is not None or kind != 'user'):
                    continue
                if row is None:
                    if kind == 'user':
                        if users is None:
                            users = conn.execute("SELECT COUNT(*) AS total FROM spend_limits WHERE kind='user'"
                                                 ).fetchone()['total']
                        if users >= MAX_USER_LIMITS:
                            raise SpendLimitCapacity()
                        users += 1
                    revision = self._first_revision_in(conn, identity) if kind == 'user' else 1
                    conn.execute(f'INSERT INTO spend_limits({_COLUMNS}) VALUES(?,?,?,?,?,?,?)',
                                 (identity, kind, subject, change.limit_usd, revision, label, stamp))
                    action = 'spend_limit.created'
                else:
                    revision = row['revision'] + 1
                    if conn.execute('''UPDATE spend_limits SET limit_usd=?,revision=?,updated_by=?,updated_at=?
                            WHERE id=? AND revision=?''', (change.limit_usd, revision, label, stamp, identity,
                                                           row['revision'])).rowcount != 1:
                        raise StaleRevision()
                    action = 'spend_limit.updated'
                record_event_in(conn, action, label, 'spend_limit', identity, {
                    'kind': kind, 'limit_usd': change.limit_usd, 'previous_usd': previous, 'revision': revision})
            return self.listing_in(conn)

    def delete(self, limit_id: str, revision: int, actor) -> dict:
        """Remove one person's override so the default applies again."""
        if type(revision) is not int:
            raise TypeError('Spend limit revisions are integers.')
        identity, kind, _ = parse_id(limit_id)
        if kind != 'user':
            raise InvalidSpendLimit('Only per-person limits can be deleted. Save no limit to clear this one.')
        label = actor_label(actor)
        with self.store.connect() as conn:
            conn.begin_write()
            label = self._authorized_in(conn, actor, label)
            row = conn.execute(f'SELECT {_COLUMNS} FROM spend_limits WHERE id=?', (identity,)).fetchone()
            if row is None:
                raise SpendLimitNotFound()
            if row['revision'] != revision or conn.execute(
                    'DELETE FROM spend_limits WHERE id=? AND revision=?', (identity, revision)).rowcount != 1:
                raise StaleRevision()
            record_event_in(conn, 'spend_limit.deleted', label, 'spend_limit', identity, {
                'kind': kind, 'limit_usd': None,
                'previous_usd': None if row['limit_usd'] is None else float(row['limit_usd']),
                'revision': revision})
        return {'id': identity, 'deleted': True}
