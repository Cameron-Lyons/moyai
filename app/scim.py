"""SCIM 2.0 Users and Groups provisioning with bearer tokens stored as hashes.

The supported schema, filter and PATCH subset is explicit. Provisioning never
creates sign-in sessions or replaces verified Google, Access or OIDC identities; it
controls whether an email may act (deactivation and deletion revoke access) and
which directory groups receive custom-role grants. Deleted resources keep
tombstones so a reused userName or externalId cannot revive old grants.

Attribute names are case-insensitive (RFC 7643 section 2.1). Extension
attributes and the core User attributes Moyai does not store (phone numbers,
addresses, passwords, ...) are accepted and ignored in every request form, so an
identity provider's unrelated mapping never voids a deactivation sent in the
same atomic PATCH. Unknown core attributes still fail explicitly.

Every request authenticates with a bearer token; the browser session never
does. A malformed header is refused before any connection opens, and no write
requests the canonical exclusive writer until a plain read has accepted the
credential (/scim/v2 is reachable without Access). Writes re-authenticate inside
the writer, so a token revoked before a write is admitted cannot change the
directory, and record one governance audit event per change. Token use is
best-effort bookkeeping: it never fails a request and never waits long for a
lock held by a writer.

A rename never blocks deprovisioning: userName is immutable, but a write whose
result is inactive keeps the stored userName and applies (Entra bundles the
changed userName with active=false). Group PATCH changes only the submitted
membership delta and answers 204 unless attributes/excludedAttributes asks for
the resource, which is then read after commit; Group list pages include
members only for attributes=members. Text must be valid Unicode without NUL.
All database work and response rendering run off the event loop.

Schema lives in the canonical initializers; keep the import alias below instead
of defining initialize_schema here.
"""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .database import INTEGRITY_ERRORS, DatabaseBusyError, DatabaseError
from .db import database
from .enterprise_roles import (
    GovernanceForbidden,
    GovernanceInvalid,
    GovernanceNotFound,
    narrow_group_in,
)
from .governance_audit import record_event_in, timestamp
from .schema_initializers import initialize_scim as initialize_schema

log = logging.getLogger(__name__)

CORE = 'urn:ietf:params:scim:schemas:core:2.0:'
API = 'urn:ietf:params:scim:api:messages:2.0:'
MEDIA = 'application/scim+json'
MAX_RESULTS = 100
MAX_MEMBERS = 10000  # Distinct member references one request may submit, not the group's size.
MAX_BODY = 2 * 1024 * 1024
MAX_OPERATIONS = 100
CHUNK = 500  # Below SQLite's historical 999 bound-variable limit.
TOKEN_USE_INTERVAL = timedelta(minutes=5)
TOKEN_USE_WAIT_MS = 250  # Bookkeeping never waits longer for a lock.
UNAUTHENTICATED = 'A valid provisioning bearer credential is required.'
MISSING = 'The requested resource does not exist.'
TOKEN = re.compile(r'(?i:bearer)[ \t]+(moyai_scim_([0-9a-f]{32})\.[A-Za-z0-9_-]{43})')
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
TEXT_FIELDS = ('displayName', 'title', 'userType', 'nickName', 'preferredLanguage', 'locale', 'timezone', 'profileUrl')
USER_FIELDS = ('userName', 'externalId', 'active', 'name', 'emails', *TEXT_FIELDS)
GROUP_FIELDS = ('displayName', 'externalId', 'members')
NAME_FIELDS = ('formatted', 'givenName', 'familyName', 'middleName', 'honorificPrefix', 'honorificSuffix')
EMAIL_FIELDS = ('value', 'type', 'primary', 'display')
MEMBER_FIELDS = ('value', '$ref', 'display', 'type')
# Core User attributes accepted and not stored; they never authorize anything.
IGNORED = {'User': ('password', 'phoneNumbers', 'ims', 'photos', 'addresses', 'entitlements', 'roles',
                    'x509Certificates'), 'Group': ()}
READ_ONLY = ('id', 'meta', 'groups')
ALWAYS = {'schemas', 'id', 'meta'}
REQUIRED = {'User': {'userName'}, 'Group': {'displayName'}}
FILTER = re.compile(r'\s*([a-zA-Z]+)\s+eq\s+("(?:[^"\\]|\\.)*"|true|false)\s*', re.IGNORECASE)
VALUE_PATH = re.compile(
    r'([a-z][a-z0-9$_-]*)\[\s*([a-z][a-z0-9$_-]*)\s+eq\s+("(?:[^"\\]|\\.)*")\s*\](?:\.([a-z][a-z0-9$_-]*))?', re.IGNORECASE)


def lowered(*names):
    return {name.lower(): name for name in names}


FIELDS = {'User': lowered(*USER_FIELDS), 'Group': lowered(*GROUP_FIELDS)}
IGNORED_NAMES = {kind: lowered(*names) for kind, names in IGNORED.items()}
READ_ONLY_NAMES = lowered(*READ_ONLY)
SUB_FIELDS = {'name': lowered(*NAME_FIELDS), 'emails': lowered(*EMAIL_FIELDS), 'members': lowered(*MEMBER_FIELDS)}


class ScimError(HTTPException):
    def __init__(self, status, detail, kind=''):
        super().__init__(status, detail)
        self.status, self.kind = status, kind


def error_response(error):
    body = {'schemas': [API + 'Error'], 'status': str(error.status), 'detail': error.detail}
    if error.kind:
        body['scimType'] = error.kind
    headers = {'Cache-Control': 'no-store'}
    if error.status == 401:
        headers['WWW-Authenticate'] = 'Bearer'
    if error.status == 503:
        headers['Retry-After'] = '5'
    return JSONResponse(body, status_code=error.status, media_type=MEDIA, headers=headers)


class ScimRoute(APIRoute):
    """Every outcome, including database pressure, is a SCIM response."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def scim_handler(request):
            try:
                response = await handler(request)
                response.headers['cache-control'] = 'no-store'
                return response
            except ScimError as error:
                return error_response(error)
            except HTTPException as error:
                return error_response(ScimError(error.status_code, str(error.detail)))
            except RequestValidationError:
                return error_response(ScimError(400, 'The request is not valid.', 'invalidSyntax'))
            except UnicodeError:
                # Validation rejects unencodable text first; never a non-SCIM 500.
                return error_response(ScimError(400, 'Text values must be valid Unicode.', 'invalidValue'))
            except INTEGRITY_ERRORS:
                return error_response(ScimError(409, 'A resource with this unique identity already exists.', 'uniqueness'))
            except DatabaseBusyError:
                return error_response(ScimError(503, 'The directory is busy. Retry the request.'))
            except DatabaseError:
                return error_response(ScimError(503, 'The directory is unavailable. Retry the request.'))
        return scim_handler


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    label: str = Field(min_length=1, max_length=80)


def valid_text(value):
    """Storable and renderable text: no NUL, and UTF-8 encodable (no lone surrogates).

    json.loads accepts an escaped lone surrogate ("\\ud800"); the database
    drivers and the response renderer cannot encode it, and PostgreSQL rejects
    NUL, so either would surface as a 500 or a retryable 503 instead of a 400.
    """
    if not isinstance(value, str) or '\x00' in value:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def value_text(value, field, *, required=False, maximum=1000):
    if value is None and not required:
        return ''
    if not isinstance(value, str) or len(value) > maximum or not valid_text(value) or (required and not value.strip()):
        raise ScimError(400, f'{field} must be a valid string.', 'invalidValue')
    return value.strip()


def resource_identity(identity):
    """A path id that could name a stored resource; any other id simply does not exist."""
    if identity is not None and (len(identity) > 1000 or not valid_text(identity)):
        raise ScimError(404, MISSING)
    return identity


def _credential(header):
    """The bearer credential's match; a malformed header is 401 before any connection opens."""
    match = TOKEN.fullmatch(header) if isinstance(header, str) else None
    if match is None:
        raise ScimError(401, UNAUTHENTICATED)
    return match


def canonical(value, names, what):
    """value's keys renamed case-insensitively to names; unknown keys are kept for the caller to judge."""
    if not isinstance(value, dict):
        raise ScimError(400, f'{what} must be an object.', 'invalidValue')
    result = {}
    for key, item in value.items():
        name = names.get(key.lower(), key) if isinstance(key, str) else key
        if name in result:
            raise ScimError(400, 'Send each attribute once; attribute names are case-insensitive.', 'invalidSyntax')
        result[name] = item
    return result


def schemas_valid(schemas, kind):
    # Extensions may be declared; their attributes are ignored, never trusted.
    return (isinstance(schemas, list) and all(isinstance(item, str) for item in schemas)
            and (CORE + kind).lower() in {item.lower() for item in schemas}
            and all(item.lower() == (CORE + kind).lower() or item.lower().startswith('urn:') for item in schemas))


def document(body, kind):
    if not isinstance(body, dict):
        raise ScimError(400, 'The request body must be a JSON object.', 'invalidSyntax')
    result = {}
    for key, value in canonical(body, {**FIELDS[kind], 'schemas': 'schemas'}, 'The request body').items():
        if not isinstance(key, str):
            raise ScimError(400, 'The request body must be a JSON object.', 'invalidSyntax')
        if key == 'schemas':
            if not schemas_valid(value, kind):
                raise ScimError(400, 'Only the advertised core resource schema and extensions are supported.', 'invalidValue')
        elif key in FIELDS[kind].values():
            result[key] = value
        elif not (key.lower() in READ_ONLY_NAMES or key.lower() in IGNORED_NAMES[kind] or key.lower().startswith('urn:')):
            raise ScimError(400, 'The request contains unsupported attributes.', 'invalidValue')
    return result


def validate_user(body):
    body = document(body, 'User')
    email = value_text(body.get('userName'), 'userName', required=True, maximum=254).lower()
    if not EMAIL.fullmatch(email):
        raise ScimError(400, 'userName must be a work email address.', 'invalidValue')
    active = body.get('active', True)
    if type(active) is not bool:
        raise ScimError(400, 'active must be a boolean.', 'invalidValue')
    result = {'userName': email, 'active': active}
    if 'externalId' in body:
        result['externalId'] = value_text(body['externalId'], 'externalId', maximum=1000)
    for field in TEXT_FIELDS:
        if field in body:
            result[field] = value_text(body[field], field, maximum=1000)
    if body.get('name') is not None:
        name = canonical(body['name'], SUB_FIELDS['name'], 'name')
        if set(name) - set(NAME_FIELDS):
            raise ScimError(400, 'name contains unsupported attributes.', 'invalidValue')
        result['name'] = {key: value_text(value, 'name.' + key) for key, value in name.items()}
    if body.get('emails') is not None:
        if not isinstance(body['emails'], list) or len(body['emails']) > 20:
            raise ScimError(400, 'emails must be an array with at most 20 entries.', 'invalidValue')
        result['emails'] = []
        for item in body['emails']:
            item = canonical(item, SUB_FIELDS['emails'], 'Each email')
            if set(item) - set(EMAIL_FIELDS):
                raise ScimError(400, 'emails contains unsupported attributes.', 'invalidValue')
            entry: dict[str, str | bool] = {
                key: value_text(value, 'emails.' + key, required=key == 'value', maximum=254)
                for key, value in item.items() if key != 'primary'}
            if not isinstance(entry.get('value'), str) or not EMAIL.fullmatch(str(entry['value']).lower()):
                raise ScimError(400, 'Each email requires a valid value.', 'invalidValue')
            if 'primary' in item:
                if type(item['primary']) is not bool:
                    raise ScimError(400, 'emails.primary must be a boolean.', 'invalidValue')
                entry['primary'] = item['primary']
            result['emails'].append(entry)
        if sum(item.get('primary', False) for item in result['emails']) > 1:
            raise ScimError(400, 'Only one email can be primary.', 'invalidValue')
    return result


def member_ids(members, what='members'):
    """Distinct member ids in submission order; duplicates are one reference."""
    if not isinstance(members, list):
        raise ScimError(400, f'{what} must be an array of member references.', 'invalidValue')
    selected = {}
    for member in members:
        member = canonical(member, SUB_FIELDS['members'], 'Each member')
        kind = member.get('type', 'User')
        if set(member) - set(MEMBER_FIELDS) or not isinstance(kind, str) or kind.lower() != 'user':
            raise ScimError(400, 'Only User members are supported.', 'invalidValue')
        selected[value_text(member.get('value'), 'members.value', required=True, maximum=100)] = None
    return list(selected)


def validate_group(body, *, limit=True):
    body = document(body, 'Group')
    display = value_text(body.get('displayName'), 'displayName', required=True, maximum=254)
    external = value_text(body.get('externalId'), 'externalId', maximum=1000)
    members = member_ids(body.get('members') if body.get('members') is not None else [])
    if limit and len(members) > MAX_MEMBERS:
        raise ScimError(400, f'Send at most {MAX_MEMBERS} members in one request.', 'invalidValue')
    return display, external, members


def patch_active(value):
    # Entra sends active as the strings "True"/"False" unless its compliance
    # flag is set. Accept only those literals, and only through PATCH.
    if isinstance(value, str) and value.strip().lower() in {'true', 'false'}:
        return value.strip().lower() == 'true'
    return value


def parse_path(raw, kind):
    """('attr', name) | ('name', sub) | ('emails', filter, literal, sub) | ('member', id) | ('ignore',)."""
    path = value_text(raw, 'path', required=True, maximum=2000)
    core = (CORE + kind + ':').lower()
    if path.lower().startswith(core):
        path = path[len(core):]
    elif path.lower().startswith('urn:') and not path.lower().startswith(CORE.lower()):
        return ('ignore',)  # Extension attributes, such as the enterprise User, are not stored.
    if match := VALUE_PATH.fullmatch(path):
        attribute, field, sub = match[1].lower(), match[2].lower(), match[4]
        try:
            literal = json.loads(match[3])
        except ValueError:
            raise ScimError(400, 'Invalid PATCH path filter.', 'invalidPath') from None
        if not valid_text(literal):
            raise ScimError(400, 'Invalid PATCH path filter.', 'invalidPath')
        if kind == 'User' and attribute == 'emails' and field in {'type', 'value'} and (
                sub is None or sub.lower() in SUB_FIELDS['emails']):
            return ('emails', field, literal, SUB_FIELDS['emails'][sub.lower()] if sub else None)
        if kind == 'Group' and attribute == 'members' and field == 'value' and sub is None:
            return ('member', literal)
        if attribute in IGNORED_NAMES[kind]:
            return ('ignore',)
        raise ScimError(400, 'Unsupported PATCH path.', 'invalidPath')
    head, _, sub = path.partition('.')
    head = head.lower()
    if head in READ_ONLY_NAMES:
        raise ScimError(400, 'This attribute is read-only.', 'mutability')
    if head in IGNORED_NAMES[kind]:
        return ('ignore',)
    if not sub and head in FIELDS[kind]:
        return ('attr', FIELDS[kind][head])
    if kind == 'User' and head == 'name' and sub.lower() in SUB_FIELDS['name']:
        return ('name', SUB_FIELDS['name'][sub.lower()])
    raise ScimError(400, 'Unsupported PATCH path.', 'invalidPath')


def merged(result, kind, op, attribute, value):
    """RFC 7644 add/replace semantics for complex and multi-valued attributes."""
    if kind == 'User' and attribute == 'active':
        return patch_active(value)
    if kind == 'User' and attribute == 'name':
        return {**result.get('name', {}), **canonical(value, SUB_FIELDS['name'], 'name')}
    if kind == 'User' and attribute == 'emails' and op == 'add':
        if not isinstance(value, list):
            raise ScimError(400, 'emails must be an array.', 'invalidValue')
        emails = [dict(item) for item in result.get('emails', [])]
        seen = {(str(item.get('value', '')).lower(), item.get('type')) for item in emails}
        for item in value:
            item = canonical(item, SUB_FIELDS['emails'], 'Each email')
            key = (str(item.get('value', '')).lower(), item.get('type'))
            if key in seen:
                continue
            if item.get('primary') is True:
                for other in emails:
                    if other.get('primary'):
                        other['primary'] = False
            seen.add(key)
            emails.append(item)
        return emails
    return value


def patch_email(result, op, field, literal, sub, value):
    """Entra's `emails[type eq "work"].value` form: change, add or remove the matching entries."""
    emails = [dict(item) for item in result.get('emails') or []]
    matches = [index for index, item in enumerate(emails) if isinstance(item.get(field), str)
               and isinstance(literal, str) and item[field].lower() == literal.lower()]
    if op == 'remove':
        if sub is None or sub == 'value':
            emails = [item for index, item in enumerate(emails) if index not in matches]
        else:
            for index in matches:
                emails[index].pop(sub, None)
    else:
        change = canonical(value, SUB_FIELDS['emails'], 'The email') if sub is None else {sub: value}
        if not matches:
            emails.append({field: literal})
            matches = [len(emails) - 1]
        for index in matches:
            emails[index].update(change)
        if change.get('primary') is True:
            for index, item in enumerate(emails):
                if index not in matches and item.get('primary'):
                    item['primary'] = False
    result['emails'] = emails


class Membership:
    """A Group PATCH's membership change, computed without the group's member list.

    present(user_id) reports stored membership with one indexed lookup and is
    asked only by filtered removals. clear: a replace, or a remove of every
    member, after which stored members outside added leave. added keeps
    submission order; added and removed never overlap.
    """

    def __init__(self, present):
        self.present, self.clear, self.added, self.removed = present, False, {}, set()

    def contains(self, user):
        if user in self.added:
            return True
        return not self.clear and user not in self.removed and self.present(user)

    def add(self, users):
        for user in users:
            self.removed.discard(user)
            self.added[user] = None

    def remove(self, users):
        for user in users:
            self.added.pop(user, None)
            self.removed.add(user)

    def replace(self, users):
        self.clear, self.added, self.removed = True, dict.fromkeys(users), set()


def patch_document(original, body, kind, identity=None, members=None):
    """Apply a PatchOp atomically to a resource document; nothing is written here.

    A Group document holds only its own attributes; membership operations
    update members, a Membership, so a join or leave never loads, copies or
    revalidates the stored members. At most MAX_MEMBERS distinct member
    references may be submitted per request; the resulting size is not capped.
    """
    if kind == 'Group' and not isinstance(members, Membership):
        raise TypeError('Group patches need a Membership.')
    if not isinstance(body, dict):
        raise ScimError(400, 'Use the SCIM PatchOp schema and Operations array.', 'invalidSyntax')
    body = canonical(body, {'schemas': 'schemas', 'operations': 'Operations'}, 'The request body')
    schemas = body.get('schemas')
    if (set(body) - {'schemas', 'Operations'} or not isinstance(schemas, list)
            or [str(item).lower() for item in schemas] != [(API + 'PatchOp').lower()]):
        raise ScimError(400, 'Use the SCIM PatchOp schema and Operations array.', 'invalidSyntax')
    operations = body.get('Operations')
    if not isinstance(operations, list) or not operations or len(operations) > MAX_OPERATIONS:
        raise ScimError(400, f'Operations must contain between 1 and {MAX_OPERATIONS} operations.', 'invalidSyntax')
    result = json.loads(json.dumps(original))
    result.pop('schemas', None)
    if kind == 'Group':
        result.pop('members', None)
    else:
        members = None
    submitted = 0

    def references(value):
        nonlocal submitted
        ids = member_ids(value)
        submitted += len(ids)
        if submitted > MAX_MEMBERS:
            raise ScimError(400, f'Send at most {MAX_MEMBERS} members in one request.', 'invalidValue')
        return ids

    def apply(op, target, value):
        if target[0] == 'ignore':
            return
        if target[0] == 'name':
            name = dict(result.get('name') or {})
            if op == 'remove':
                name.pop(target[1], None)
            else:
                name[target[1]] = value
            result['name'] = name
            return
        if target[0] == 'emails':
            _, field, literal, sub = target
            patch_email(result, op, field, literal, sub, value)
            return
        if members is None:  # Membership targets parse only for Groups.
            if target[0] == 'member' or target[1] == 'members':
                raise ScimError(400, 'Unsupported PATCH path.', 'invalidPath')
        elif target[0] == 'member':
            if op != 'remove':
                raise ScimError(400, 'Filtered membership paths support remove only.', 'invalidPath')
            if not members.contains(target[1]):
                raise ScimError(400, 'The member path did not match a resource.', 'noTarget')
            members.remove([target[1]])
            return
        attribute = target[1]
        if attribute == 'members' and members is not None:
            if op == 'remove':
                # Entra names removed members in a value array; no value empties the group.
                if value is None:
                    members.replace([])
                else:
                    members.remove(references(value))
            elif op == 'replace':
                members.replace(references(value))
            else:
                members.add(references(value))
            return
        if op == 'remove':
            if attribute in REQUIRED[kind]:
                raise ScimError(400, 'A required attribute cannot be removed.', 'mutability')
            result.pop(attribute, None)
        else:
            result[attribute] = merged(result, kind, op, attribute, value)

    for operation in operations:
        operation = canonical(operation, lowered('op', 'path', 'value'), 'Each operation')
        if set(operation) - {'op', 'path', 'value'}:
            raise ScimError(400, 'Invalid PATCH operation.', 'invalidSyntax')
        op = operation.get('op', '')
        if not isinstance(op, str) or op.lower() not in {'add', 'replace', 'remove'}:
            raise ScimError(400, 'Unsupported PATCH operation.', 'invalidSyntax')
        op = op.lower()
        if op != 'remove' and 'value' not in operation:
            raise ScimError(400, 'PATCH add and replace require a value.', 'invalidValue')
        if operation.get('path') not in (None, ''):
            apply(op, parse_path(operation['path'], kind), operation.get('value'))
            continue
        if op == 'remove':
            raise ScimError(400, 'A remove operation requires a path.', 'noTarget')
        value = operation.get('value')
        if not isinstance(value, dict):
            raise ScimError(400, 'A PATCH value without a path must be an object.', 'invalidValue')
        for key, item in value.items():
            if isinstance(key, str) and key.lower() == 'id' and identity is not None and item == identity:
                continue  # Okta repeats the unchanged resource ID when renaming a group.
            # No-path keys are attribute paths too: dotted, filtered and URN forms.
            apply(op, parse_path(key, kind), item)
    return result


def _cursor(values):
    return base64.urlsafe_b64encode(json.dumps(values, separators=(',', ':')).encode()).decode().rstrip('=')


def _read_cursor(cursor):
    try:
        values = json.loads(base64.urlsafe_b64decode(cursor + '=' * (-len(cursor) % 4)))
    except (ValueError, binascii.Error, UnicodeError):
        values = None
    if not (isinstance(values, list) and len(values) == 2 and all(valid_text(item) for item in values)):
        raise GovernanceInvalid('Reload the directory and try again.')
    return values


def _display_name(profile):
    name = profile.get('name') or {}
    joined = ' '.join(part for part in (name.get('givenName'), name.get('familyName')) if part)
    return profile.get('displayName') or name.get('formatted') or joined or ''


def _token_view(row):
    return {'id': row['id'], 'label': row['label'], 'prefix': row['prefix'], 'created_at': row['created_at'],
            'created_by': row['created_by'], 'last_used_at': row['last_used_at'] or None,
            'revoked_at': row['revoked_at'] or None}


def _stale_use(last_used_at):
    try:
        return datetime.fromisoformat(last_used_at) < datetime.now(UTC) - TOKEN_USE_INTERVAL
    except (TypeError, ValueError):
        return True


class Scim:
    """SCIM protocol, storage and the provisioning admin library over a canonical Store.

    user_roles supplies eligibility, built-in roles and active administrators;
    base_url is the public origin's `/scim/v2`. Methods are synchronous; the
    router and native routes call them through threads.
    """

    def __init__(self, store, user_roles, *, base_url: str):
        self.store, self.roles = store, user_roles
        self.base_url = base_url.rstrip('/')
        if store.schema_updates:
            from .schema_initializers import initialize_enterprise_roles, initialize_governance_audit
            initialize_schema(store)
            initialize_enterprise_roles(store)  # Group writes read grants to advance access epochs.
            initialize_governance_audit(store)

    # Authentication

    @staticmethod
    def _token_in(conn, header):
        match = _credential(header)
        row = conn.execute("SELECT id,label,token_hash,last_used_at FROM scim_tokens WHERE id=? AND revoked_at=''",
                           (match[2],)).fetchone()
        if row is None or not hmac.compare_digest(row['token_hash'], hashlib.sha256(match[1].encode()).hexdigest()):
            raise ScimError(401, UNAUTHENTICATED)
        return {'id': row['id'], 'label': row['label'], 'last_used_at': row['last_used_at']}

    def authenticate_in(self, conn, header, *, write=False):
        """The token for this request. In a write transaction a stale use time is refreshed there."""
        token = self._token_in(conn, header)
        if write and _stale_use(token['last_used_at']):
            conn.execute('UPDATE scim_tokens SET last_used_at=? WHERE id=?', (timestamp(), token['id']))
            token['last_used_at'] = None
        return token

    def admit(self, header):
        """The credential, accepted on a plain read before a write requests the canonical writer.

        Otherwise anyone could queue for the exclusive writer, stalling every
        workspace writer and admission behind it. Writes still recheck the
        credential under the writer, so a revocation in between wins.
        """
        _credential(header)
        with self.store.connect() as conn:
            return self._token_in(conn, header)

    def touch(self, token):
        """Record read use at most once per TOKEN_USE_INTERVAL; never for a revoked token.

        Best effort: lock waits stop after TOKEN_USE_WAIT_MS, and a busy or
        failing database skips the bookkeeping instead of failing a request
        whose result is already computed.
        """
        if not _stale_use(token['last_used_at']):
            return
        stamp = timestamp()
        cutoff = (datetime.now(UTC) - TOKEN_USE_INTERVAL).isoformat(timespec='microseconds')
        try:
            # An independent row: scoped writers share the canonical lock instead of excluding them.
            with self.store.connect(write_scope='scim-token-use') as conn:
                if self.store.database:
                    conn.execute(f"SET LOCAL lock_timeout = '{TOKEN_USE_WAIT_MS}ms'")
                else:
                    conn.execute(f'PRAGMA busy_timeout = {TOKEN_USE_WAIT_MS}')
                conn.execute('''UPDATE scim_tokens SET last_used_at=? WHERE id=? AND revoked_at=''
                    AND (last_used_at='' OR last_used_at<?)''', (stamp, token['id'], cutoff))
        except (DatabaseError, sqlite3.Error) as error:
            log.warning('Provisioning token use was not recorded: %s', type(error).__name__)

    def authenticate(self, header):
        _credential(header)
        with self.store.connect() as conn:
            token = self._token_in(conn, header)
        self.touch(token)
        return token

    # Resources

    def guard_admins_in(self, conn, email):
        # Called before email's account becomes inactive. Directory writes
        # change activity, never roles, and only email's live row, so the active
        # administrators afterwards are the current ones less email. A write may
        # not remove the last one, but it is not blamed for an earlier loss.
        # Only an eligible administrator holder pays for the full computation.
        if (self.roles.eligible(email) and self.roles.role_in(conn, email) == 'admin'
                and self.roles.admins_in(conn) == {email}):
            raise ScimError(409, 'Keep at least one active administrator. Promote another user first.')

    def resource_in(self, conn, kind, identity, *, related=True):
        table = 'scim_users' if kind == 'User' else 'scim_groups'
        row = conn.execute(f"SELECT * FROM {table} WHERE id=? AND deleted_at=''", (identity,)).fetchone()
        if not row:
            raise ScimError(404, MISSING)
        return self._resource(row, kind, self._related_in(conn, kind, [identity])[identity] if related else None)

    def _related_in(self, conn, kind, identities):
        """{id: groups (Users) or members (Groups) in id order} for at most CHUNK resources, in one query."""
        if kind == 'User':
            query = '''SELECT m.user_id AS owner,g.id AS id,g.display_name AS display FROM scim_groups g
                JOIN scim_group_members m ON m.group_id=g.id WHERE m.user_id IN ({}) AND g.deleted_at='' ORDER BY g.id'''
            path, link = '/Groups/', 'direct'
        else:
            query = '''SELECT m.group_id AS owner,u.id AS id,u.user_name AS display FROM scim_users u
                JOIN scim_group_members m ON m.user_id=u.id WHERE m.group_id IN ({}) AND u.deleted_at='' ORDER BY u.id'''
            path, link = '/Users/', 'User'
        related = {identity: [] for identity in identities}
        for row in conn.execute(query.format(','.join('?' * len(identities))), identities):
            related[row['owner']].append({'value': row['id'], 'display': row['display'], 'type': link,
                                          '$ref': self.base_url + path + row['id']})
        return related

    def _resource(self, row, kind, related):
        """The SCIM representation of a stored row; related None omits groups or members."""
        result = json.loads(row['profile']) if kind == 'User' else {'displayName': row['display_name']}
        result.update(schemas=[CORE + kind], id=row['id'])
        if row['external_id']:
            result['externalId'] = row['external_id']
        if kind == 'User':
            result.update(userName=row['user_name'], active=bool(row['active']))
        if related is not None:
            result['groups' if kind == 'User' else 'members'] = related
        result['meta'] = {'resourceType': kind, 'created': row['created_at'], 'lastModified': row['updated_at'],
                          'location': self.base_url + '/' + kind + 's/' + row['id']}
        return result

    def write_user_in(self, conn, body, identity, token):
        created = identity is None
        saved = None if created else conn.execute(
            "SELECT user_name,active FROM scim_users WHERE id=? AND deleted_at=''", (identity,)).fetchone()
        if not created and saved is None:
            raise ScimError(404, MISSING)
        data = validate_user(body)
        identity = identity or uuid4().hex
        external = data.get('externalId', '')
        # Renaming would leave an old verified cookie ungoverned. Identity
        # migrations need an explicit account-linking workflow instead. A
        # rename never voids deprovisioning, though: after a UPN change Entra
        # sends the new userName with every update, including active=false, so
        # an inactive result keeps the stored userName and applies the rest.
        renamed = saved is not None and saved['user_name'] != data['userName']
        if saved is not None and renamed:
            if data['active']:
                raise ScimError(400, 'userName cannot be changed; deactivate the old identity and provision a new one.', 'mutability')
            data['userName'] = saved['user_name']
        if external and conn.execute("SELECT 1 FROM scim_users WHERE external_id=? AND external_id!='' AND deleted_at='' AND id<>?",
                                     (external, identity)).fetchone():
            raise ScimError(409, 'externalId must be unique for this resource type.', 'uniqueness')
        if created and conn.execute("SELECT 1 FROM scim_users WHERE user_name=? AND deleted_at=''",
                                    (data['userName'],)).fetchone():
            raise ScimError(409, 'A user with this userName already exists.', 'uniqueness')
        if not data['active']:
            self.guard_admins_in(conn, data['userName'])
        stamp = timestamp()
        was = None if saved is None else bool(saved['active'])
        if created:
            # An inactive creation, or a userName reprovisioned after deletion
            # (a new id), starts with history and never reads as untouched.
            epoch = int(not data['active'] or conn.execute(
                "SELECT 1 FROM scim_users WHERE user_name=? AND deleted_at<>'' LIMIT 1",
                (data['userName'],)).fetchone() is not None)
        else:
            epoch = int(bool(was) and not data['active'])  # Deactivation advances the access epoch.
        profile = {key: value for key, value in data.items() if key not in {'externalId', 'userName', 'active'}}
        # access_epoch in VALUES is a new row's epoch, or an existing row's increment.
        conn.execute('''INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,
                revision,access_epoch)
            VALUES(?,?,?,?,?,'',?,?,1,?) ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,
            profile=excluded.profile,active=excluded.active,updated_at=excluded.updated_at,revision=scim_users.revision+1,
            access_epoch=scim_users.access_epoch+excluded.access_epoch''',
                     (identity, external, data['userName'], json.dumps(profile), int(data['active']), stamp, stamp, epoch))
        action = ('created' if created else 'deactivated' if was and not data['active']
                  else 'reactivated' if was is False and data['active'] else 'updated')
        details = {'token_id': token['id'], 'active': data['active']}
        if renamed:
            details['rename_ignored'] = True
        record_event_in(conn, 'scim_user.' + action, token['label'], 'scim_user', identity, details)
        return identity

    def write_group_in(self, conn, body, identity, token):
        """POST or PUT: the submitted document replaces the group, members included."""
        created = identity is None
        if not created and not conn.execute("SELECT 1 FROM scim_groups WHERE id=? AND deleted_at=''", (identity,)).fetchone():
            raise ScimError(404, MISSING)
        display, external, members = validate_group(body)
        identity = identity or uuid4().hex
        existing = set() if created else {row['user_id'] for row in conn.execute(
            'SELECT user_id FROM scim_group_members WHERE group_id=?', (identity,))}
        selected = set(members)
        return self._save_group_in(conn, identity, display, external, sorted(selected - existing),
                                   sorted(existing - selected), token, created=created)

    def patch_group_in(self, conn, body, identity, token):
        """A Group PatchOp: its own attributes plus the submitted membership delta.

        Work under the writer is proportional to the request, never to the
        group: stored members are looked up only for the submitted references,
        except that a replace or a remove of every member reads the member list.
        """
        current = self.resource_in(conn, 'Group', identity, related=False)
        original = {key: current[key] for key in ('displayName', 'externalId') if key in current}
        membership = Membership(lambda user: conn.execute(
            'SELECT 1 FROM scim_group_members WHERE group_id=? AND user_id=?', (identity, user)).fetchone() is not None)
        display, external, _ = validate_group(patch_document(original, body, 'Group', identity, membership))
        wanted = list(membership.added)
        if membership.clear:
            stored = {row['user_id'] for row in conn.execute(
                'SELECT user_id FROM scim_group_members WHERE group_id=?', (identity,))}
            removed = sorted(stored - set(wanted))
        else:
            stored = set()
            references = [*wanted, *membership.removed]
            for offset in range(0, len(references), CHUNK):
                chunk = references[offset:offset + CHUNK]
                stored.update(row['user_id'] for row in conn.execute(
                    f"SELECT user_id FROM scim_group_members WHERE group_id=? AND user_id IN ({','.join('?' * len(chunk))})",
                    [identity, *chunk]))
            removed = sorted(membership.removed & stored)
        return self._save_group_in(conn, identity, display, external, sorted(set(wanted) - stored), removed, token,
                                   created=False)

    def _save_group_in(self, conn, identity, display, external, added, removed, token, *, created):
        """Upsert the group row and change only the membership delta, in batches."""
        if external and conn.execute("SELECT 1 FROM scim_groups WHERE external_id=? AND external_id!='' AND deleted_at='' AND id<>?",
                                     (external, identity)).fetchone():
            raise ScimError(409, 'externalId must be unique for this resource type.', 'uniqueness')
        if conn.execute("SELECT 1 FROM scim_groups WHERE display_key=? AND deleted_at='' AND id<>?",
                        (display.casefold(), identity)).fetchone():
            raise ScimError(409, 'A group with this displayName already exists.', 'uniqueness')
        for offset in range(0, len(added), CHUNK):
            chunk = added[offset:offset + CHUNK]
            found = conn.execute(f"SELECT COUNT(*) AS n FROM scim_users WHERE deleted_at='' AND id IN ({','.join('?' * len(chunk))})",
                                 chunk).fetchone()['n']
            if found != len(chunk):
                raise ScimError(400, 'A member must reference an existing provisioned user.', 'invalidValue')
        stamp = timestamp()
        conn.execute('''INSERT INTO scim_groups(id,external_id,display_name,display_key,deleted_at,created_at,updated_at,revision)
            VALUES(?,?,?,?,'',?,?,1) ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,
            display_name=excluded.display_name,display_key=excluded.display_key,updated_at=excluded.updated_at,revision=scim_groups.revision+1''',
                     (identity, external, display, display.casefold(), stamp, stamp))
        for offset in range(0, len(removed), CHUNK):
            chunk = removed[offset:offset + CHUNK]
            conn.execute(f"DELETE FROM scim_group_members WHERE group_id=? AND user_id IN ({','.join('?' * len(chunk))})",
                         [identity, *chunk])
        if removed and conn.execute('SELECT 1 FROM enterprise_group_roles WHERE group_id=? AND role_id IS NOT NULL',
                                    (identity,)).fetchone():
            # Leaving a granted group narrows access; the epoch keeps a later
            # re-add from restoring an earlier authority version.
            for offset in range(0, len(removed), CHUNK):
                chunk = removed[offset:offset + CHUNK]
                conn.execute(f"UPDATE scim_users SET access_epoch=access_epoch+1 WHERE id IN ({','.join('?' * len(chunk))})",
                             chunk)
        pairs = CHUNK // 2
        for offset in range(0, len(added), pairs):
            chunk = added[offset:offset + pairs]
            conn.execute('INSERT INTO scim_group_members(group_id,user_id) VALUES ' + ','.join(['(?,?)'] * len(chunk)),
                         [value for user in chunk for value in (identity, user)])
        record_event_in(conn, 'scim_group.' + ('created' if created else 'updated'), token['label'], 'scim_group',
                        identity, {'token_id': token['id'], 'members_added': len(added), 'members_removed': len(removed)})
        return identity

    @staticmethod
    def projection(params, kind):
        """RFC 7644 attributes/excludedAttributes for supported top-level attributes."""
        attributes, excluded = params.get('attributes'), params.get('excludedAttributes')
        if attributes is not None and excluded is not None:
            raise ScimError(400, 'Use either attributes or excludedAttributes, not both.', 'invalidValue')
        value = attributes if attributes is not None else excluded
        if value is None:
            return None
        known = {name.lower(): name for name in ({*USER_FIELDS, 'groups'} if kind == 'User' else set(GROUP_FIELDS)) | ALWAYS}
        prefix = (CORE + kind + ':').lower()
        names = set()
        for item in value.split(','):
            item = item.strip()
            item = item[len(prefix):] if item.lower().startswith(prefix) else item
            if item.lower() not in known:
                raise ScimError(400, 'attributes and excludedAttributes accept supported top-level attribute names.', 'invalidValue')
            names.add(known[item.lower()])
        return attributes is not None, names

    @staticmethod
    def related(selection, kind):
        if selection is None:
            return True
        include, names = selection
        return (('groups' if kind == 'User' else 'members') in names) == include

    @staticmethod
    def project(resource, selection, kind):
        if selection is None:
            return resource
        include, names = selection
        keep = ALWAYS | names if include else set(resource) - (names - ALWAYS - REQUIRED[kind])
        return {key: value for key, value in resource.items() if key in keep}

    def list_in(self, conn, params, kind):
        allowed = {'filter', 'startIndex', 'count', 'attributes', 'excludedAttributes'}
        if set(params) - allowed:
            raise ScimError(400, 'Only filter, startIndex, count, attributes and excludedAttributes query parameters are supported.', 'invalidValue')
        selection = self.projection(params, kind)
        try:
            # startIndex below 1 is 1; past the end it is an empty page (RFC 7644 3.4.2.4).
            start = max(1, int(params.get('startIndex', '1')))
            count = min(MAX_RESULTS, max(0, int(params.get('count', str(MAX_RESULTS)))))
        except (TypeError, ValueError):
            raise ScimError(400, 'startIndex and count must be integers.', 'invalidValue') from None
        table = 'scim_users' if kind == 'User' else 'scim_groups'
        predicate, args = "deleted_at=''", []
        if 'filter' in params:
            # A present but empty filter is an error, never the whole directory.
            match = FILTER.fullmatch(params['filter'])
            fields = {'id': 'id', 'externalid': 'external_id',
                      **({'username': 'user_name', 'active': 'active'} if kind == 'User' else {'displayname': 'display_key'})}
            if not match or match[1].lower() not in fields:
                raise ScimError(400, 'Only eq on id, externalId, userName/active (Users), or displayName (Groups) is supported.', 'invalidFilter')
            try:
                value = json.loads(match[2].lower() if match[2].lower() in {'true', 'false'} else match[2])
            except ValueError:
                raise ScimError(400, 'Invalid filter literal.', 'invalidFilter') from None
            if isinstance(value, str) and not valid_text(value):
                raise ScimError(400, 'Invalid filter literal.', 'invalidFilter')
            field = match[1].lower()
            if (field == 'active') != isinstance(value, bool):
                raise ScimError(400, 'The filter value has the wrong type.', 'invalidFilter')
            if field == 'username':
                value = value.lower()
            elif field == 'displayname':
                value = value.casefold()
            # The literal lets externalId lookups use their partial unique index.
            predicate += ' AND ' + fields[field] + ('=? AND external_id!=\'\'' if field == 'externalid' else '=?')
            args.append(int(value) if isinstance(value, bool) else value)
        total = conn.execute(f'SELECT COUNT(*) AS n FROM {table} WHERE {predicate}', args).fetchone()['n']
        # The offset is below the row count, so it always fits the database integer.
        rows = [] if count == 0 or start > total else conn.execute(
            f'SELECT * FROM {table} WHERE {predicate} ORDER BY id LIMIT ? OFFSET ?', [*args, count, start - 1]).fetchall()
        # A page of up to MAX_RESULTS groups never materializes their members
        # unless asked (attributes=members); GET /Groups/{id} returns them.
        related = self.related(selection, kind) if kind == 'User' else bool(
            selection is not None and selection[0] and 'members' in selection[1])
        # One membership query for the whole page, never one per resource.
        links = self._related_in(conn, kind, [row['id'] for row in rows]) if related and rows else {}
        resources = [self.project(self._resource(row, kind, links.get(row['id'])), selection, kind) for row in rows]
        return {'schemas': [API + 'ListResponse'], 'totalResults': total, 'startIndex': start,
                'itemsPerPage': len(resources), 'Resources': resources}

    def read(self, header, params, kind, identity=None):
        _credential(header)
        selection = self.projection(params, kind)
        with self.store.connect() as conn:
            conn.begin_read()
            token = self.authenticate_in(conn, header)
            if identity is None:
                result = self.list_in(conn, params, kind)
            else:
                result = self.project(self.resource_in(conn, kind, resource_identity(identity),
                                                       related=self.related(selection, kind)), selection, kind)
        self.touch(token)
        return result

    def write(self, header, params, kind, method, body, identity=None, *, admitted=False):
        """POST, PUT or PATCH; the projected resource, or None for a Group PATCH that asked for none (204).

        A Group PATCH response would cost the stored group's size, so it is read
        after commit and only when attributes/excludedAttributes asks for it.
        admitted means the caller already accepted the credential on a read
        (Scim.body); the recheck under the writer still decides.
        """
        if not admitted:
            self.admit(header)
        selection = self.projection(params, kind)
        identity = resource_identity(identity)
        with self.store.connect() as conn:
            conn.begin_write()
            # Recheck the credential under the writer: revocation wins over admission.
            token = self.authenticate_in(conn, header, write=True)
            if kind == 'User':
                if method == 'PATCH':
                    body = patch_document(self.user_document_in(conn, identity), body, kind, identity)
                identity = self.write_user_in(conn, body, identity, token)
            elif method == 'PATCH':
                self.patch_group_in(conn, body, identity, token)
            else:
                identity = self.write_group_in(conn, body, identity, token)
            deferred = kind == 'Group' and method == 'PATCH'
            result = None if deferred else self.resource_in(conn, kind, identity, related=self.related(selection, kind))
        if deferred:
            if selection is None:
                return None
            with self.store.connect() as conn:
                conn.begin_read()
                result = self.resource_in(conn, kind, identity, related=self.related(selection, kind))
        return self.project(result, selection, kind)

    def user_document_in(self, conn, identity):
        current = self.resource_in(conn, 'User', identity, related=False)
        return {key: value for key, value in current.items() if key in USER_FIELDS}

    def delete(self, header, kind, identity):
        # DELETE carries no body, so no route pre-check; never queue an
        # unauthenticated caller for the exclusive writer.
        self.admit(header)
        identity = resource_identity(identity)
        with self.store.connect() as conn:
            conn.begin_write()
            token = self.authenticate_in(conn, header, write=True)
            current = self.resource_in(conn, kind, identity, related=False)
            stamp = timestamp()
            if kind == 'User':
                self.guard_admins_in(conn, current['userName'])
                # A deleted userName is reprovisioned under a new id with history.
                conn.execute('''UPDATE scim_users SET active=0,deleted_at=?,updated_at=?,revision=revision+1,
                    access_epoch=access_epoch+1 WHERE id=?''', (stamp, stamp, identity))
                conn.execute('DELETE FROM scim_group_members WHERE user_id=?', (identity,))
            else:
                conn.execute('UPDATE scim_groups SET deleted_at=?,updated_at=?,revision=revision+1 WHERE id=?',
                             (stamp, stamp, identity))
                if conn.execute('SELECT 1 FROM enterprise_group_roles WHERE group_id=? AND role_id IS NOT NULL',
                                (identity,)).fetchone():
                    narrow_group_in(conn, identity)
                conn.execute('DELETE FROM scim_group_members WHERE group_id=?', (identity,))
            record_event_in(conn, f'scim_{kind.lower()}.deleted', token['label'], f'scim_{kind.lower()}', identity,
                            {'token_id': token['id']})

    async def body(self, request):
        # Fail unauthenticated calls before reading client content; writes
        # recheck the credential inside the transaction that changes resources.
        await database(self.authenticate, request.headers.get('authorization', ''))
        if request.headers.get('content-type', '').split(';')[0].strip().lower() not in {MEDIA, 'application/json'}:
            raise ScimError(415, 'Use application/scim+json or application/json.')
        try:
            declared = int(request.headers.get('content-length') or 0)
        except ValueError:
            raise ScimError(400, 'Invalid Content-Length.', 'invalidSyntax') from None
        if declared > MAX_BODY:
            raise ScimError(413, 'The provisioning request is too large.')
        # A chunked request declares no length: stop reading at the limit.
        raw = bytearray()
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > MAX_BODY:
                raise ScimError(413, 'The provisioning request is too large.')
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            # Deep nesting exhausts the decoder's recursion, which is not a ValueError.
            raise ScimError(400, 'The request body must be valid JSON.', 'invalidSyntax') from None

    # Provisioning administration

    def directory(self, cursor=None, limit=50, actor=None):
        """GET /api/admin/scim. Users are keyset pages by (user_name, id).

        The complete groups, tokens and activity sections come only with the
        first page; they are None with a cursor. actor, when given, must hold
        scim.manage and decides can_create_tokens.
        """
        if type(limit) is not int or not 1 <= limit <= 200:
            raise GovernanceInvalid('Choose a page size from 1 to 200.')
        after = _read_cursor(cursor) if cursor else ['', '']
        groups = tokens = activity = None
        with self.store.connect() as conn:
            conn.begin_read()
            authority = self.roles.enterprise.authorize_in(conn, actor, 'scim.manage') if actor is not None else None
            # Bounded by the page: one correlated count per listed user, through idx_scim_group_members_user.
            # The redundant user_name>=? lets idx_scim_users_name start at the cursor; the OR alone cannot.
            rows = conn.execute('''SELECT u.id,u.user_name,u.profile,u.active,u.external_id,u.updated_at,
                    (SELECT COUNT(*) FROM scim_group_members m JOIN scim_groups g ON g.id=m.group_id AND g.deleted_at=''
                     WHERE m.user_id=u.id) AS groups_count
                FROM scim_users u WHERE u.deleted_at='' AND u.user_name>=? AND (u.user_name>? OR (u.user_name=? AND u.id>?))
                ORDER BY u.user_name,u.id LIMIT ?''', (after[0], after[0], after[0], after[1], limit + 1)).fetchall()
            # Load more keeps the first page's sections; recomputing them would re-aggregate every membership.
            if not cursor:
                groups = [{'id': row['id'], 'display_name': row['display_name'], 'member_count': int(row['member_count']),
                           'role_id': row['role_id'], 'role_name': row['role_name'] if row['role_id'] else None}
                          for row in conn.execute('''SELECT g.id,g.display_name,g.display_key,r.role_id,e.name AS role_name,
                                  COUNT(u.id) AS member_count FROM scim_groups g
                              LEFT JOIN scim_group_members m ON m.group_id=g.id
                              LEFT JOIN scim_users u ON u.id=m.user_id AND u.deleted_at='' AND u.active=1
                              LEFT JOIN enterprise_group_roles r ON r.group_id=g.id
                              LEFT JOIN enterprise_roles e ON e.id=r.role_id
                              WHERE g.deleted_at='' GROUP BY g.id,g.display_name,g.display_key,r.role_id,e.name
                              ORDER BY g.display_key,g.id''')]
                tokens = [_token_view(row) for row in conn.execute('''SELECT id,label,prefix,created_at,created_by,
                    last_used_at,revoked_at FROM scim_tokens ORDER BY created_at DESC,id DESC''')]
                # PostgreSQL walks idx_governance_audit_time back only in its byte order, as the audit feed does.
                order = ' COLLATE "C"' if self.store.database else ''
                activity = [{'id': row['id'], 'source': 'governance', 'action': row['action'], 'actor': row['actor'],
                             'resource_type': row['resource_type'], 'resource_id': row['resource_id'],
                             'details': json.loads(row['details']), 'created_at': row['created_at']}
                            for row in conn.execute(f'''SELECT * FROM governance_audit_events
                                WHERE resource_type IN ('scim_user','scim_group','scim_token')
                                ORDER BY created_at{order} DESC,id{order} DESC LIMIT 20''')]
        items = []
        for row in rows[:limit]:
            profile = json.loads(row['profile'])
            items.append({'id': row['id'], 'user_name': row['user_name'], 'display_name': _display_name(profile),
                          'active': bool(row['active']), 'external_id': row['external_id'],
                          'groups_count': int(row['groups_count']), 'updated_at': row['updated_at']})
        last = rows[limit - 1] if len(rows) > limit else None
        return {'base_url': self.base_url,
                'users': {'items': items, 'next_cursor': _cursor([last['user_name'], last['id']]) if last else None},
                'groups': groups, 'tokens': tokens, 'activity': activity,
                'can_create_tokens': bool(authority and authority.builtin_admin)}

    def create_token(self, label, actor):
        """(token record, bearer token). The secret is returned only here and stored as SHA-256."""
        try:
            label = TokenCreate(label=label).label
        except ValidationError:
            label = None
        if label is None or '\x00' in label:
            raise GovernanceInvalid('Name the token with 1 to 80 characters.')
        identity = uuid4().hex
        token = 'moyai_scim_' + identity + '.' + secrets.token_urlsafe(32)
        prefix = token[:19]
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self.roles.enterprise.authority_in(conn, actor)
            # Unlike viewing or revoking, issuing a credential needs the built-in
            # administrator: it controls membership, group grants and deactivation.
            if not authority.builtin_admin:
                raise GovernanceForbidden('Only a built-in administrator can create provisioning tokens.')
            conn.execute('''INSERT INTO scim_tokens(id,label,token_hash,prefix,created_by,created_at,last_used_at,revoked_at)
                VALUES(?,?,?,?,?,?,'','')''', (identity, label, hashlib.sha256(token.encode()).hexdigest(), prefix,
                                               authority.label, timestamp()))
            record_event_in(conn, 'scim_token.created', authority.label, 'scim_token', identity,
                            {'label': label, 'prefix': prefix})
            row = conn.execute('SELECT * FROM scim_tokens WHERE id=?', (identity,)).fetchone()
        return _token_view(row), token

    def revoke_token(self, token_id, actor):
        """Revoke a token (idempotent) and return its record; scim.manage."""
        with self.store.connect() as conn:
            conn.begin_write()
            authority = self.roles.enterprise.authorize_in(conn, actor, 'scim.manage')
            row = conn.execute('SELECT * FROM scim_tokens WHERE id=?', (token_id,)).fetchone()
            if row is None:
                raise GovernanceNotFound('Provisioning token not found.')
            if not row['revoked_at']:
                conn.execute('UPDATE scim_tokens SET revoked_at=? WHERE id=?', (timestamp(), token_id))
                record_event_in(conn, 'scim_token.revoked', authority.label, 'scim_token', token_id,
                                {'label': row['label'], 'prefix': row['prefix']})
                row = conn.execute('SELECT * FROM scim_tokens WHERE id=?', (token_id,)).fetchone()
        return _token_view(row)

    def router(self):
        return scim_router(self)


def _authorization(request):
    return request.headers.get('authorization', '')


def _params(request) -> dict[str, str]:
    return dict(request.query_params)


SERVICE_PROVIDER = {
    'schemas': [CORE + 'ServiceProviderConfig'],
    'patch': {'supported': True}, 'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
    'filter': {'supported': True, 'maxResults': MAX_RESULTS}, 'changePassword': {'supported': False},
    'sort': {'supported': False}, 'etag': {'supported': False},
    'authenticationSchemes': [{'type': 'oauthbearertoken', 'name': 'Provisioning bearer credential',
                               'description': 'Administrator-created random bearer credential, stored as a SHA-256 hash.',
                               'primary': True}],
    'documentationUri': 'https://www.rfc-editor.org/rfc/rfc7644',
}


def schema(kind):
    def attribute(name, data_type='string', multi=False, required=False, readonly=False, sub=None):
        value = {'name': name, 'type': data_type, 'multiValued': multi, 'required': required,
                 'caseExact': name in {'id', 'externalId'}, 'mutability': 'readOnly' if readonly else 'readWrite',
                 'returned': 'default', 'uniqueness': 'server' if name == 'userName' else 'none'}
        if sub:
            value['subAttributes'] = sub
        return value
    attributes = [attribute('externalId')]
    if kind == 'User':
        attributes += [attribute('userName', required=True), attribute('active', 'boolean'),
                       attribute('name', 'complex', sub=[attribute(name) for name in NAME_FIELDS]),
                       attribute('emails', 'complex', multi=True, sub=[attribute('value'), attribute('type'),
                                                                        attribute('display'), attribute('primary', 'boolean')])]
        attributes += [attribute(name) for name in sorted(TEXT_FIELDS)]
        attributes += [attribute('groups', 'complex', multi=True, readonly=True,
                                 sub=[attribute('value', readonly=True), attribute('$ref', 'reference', readonly=True),
                                      attribute('display', readonly=True), attribute('type', readonly=True)])]
        next(item for item in attributes if item['name'] == 'userName')['mutability'] = 'immutable'
    else:
        attributes += [attribute('displayName', required=True), attribute('members', 'complex', multi=True,
                       sub=[attribute('value'), attribute('$ref', 'reference'), attribute('display', readonly=True),
                            attribute('type')])]
    return {'schemas': [CORE + 'Schema'], 'id': CORE + kind, 'name': kind,
            'description': 'Moyai supported provisioning attributes.', 'attributes': attributes}


def _discovery(resources, identity):
    if identity:
        resources = [item for item in resources if item['id'] == identity]
        if not resources:
            raise ScimError(404, MISSING)
        return JSONResponse(resources[0], media_type=MEDIA)
    return JSONResponse({'schemas': [API + 'ListResponse'], 'totalResults': len(resources), 'startIndex': 1,
                         'itemsPerPage': len(resources), 'Resources': resources}, media_type=MEDIA)


def scim_router(service: Scim) -> APIRouter:
    """The /scim/v2 protocol router: bearer tokens only, no browser session or CSRF dependency."""
    router = APIRouter(prefix='/scim/v2', route_class=ScimRoute)

    @router.get('/ServiceProviderConfig')
    async def config(request: Request):
        await database(service.authenticate, _authorization(request))
        return JSONResponse(SERVICE_PROVIDER, media_type=MEDIA)

    @router.get('/ResourceTypes')
    @router.get('/ResourceTypes/{identity}')
    async def resource_types(request: Request, identity: str = ''):
        await database(service.authenticate, _authorization(request))
        return _discovery([{'schemas': [CORE + 'ResourceType'], 'id': kind, 'name': kind, 'endpoint': '/' + kind + 's',
                            'schema': CORE + kind, 'schemaExtensions': []} for kind in ('User', 'Group')], identity)

    @router.get('/Schemas')
    @router.get('/Schemas/{identity:path}')
    async def schemas(request: Request, identity: str = ''):
        await database(service.authenticate, _authorization(request))
        return _discovery([schema(kind) for kind in ('User', 'Group')], identity)

    for kind in ('User', 'Group'):
        _resource_routes(router, service, kind)
    return router


def render(content) -> bytes:
    """SCIM JSON bytes, as JSONResponse would render them."""
    return json.dumps(content, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _rendered(operation, *args, **kwargs):
    """Run operation and render its result in the same worker thread: large pages never block the event loop."""
    result = operation(*args, **kwargs)
    return result, None if result is None else render(result)


def _resource_routes(router, service, kind):
    collection = '/' + kind + 's'

    async def listing(request: Request):
        _, content = await database(_rendered, service.read, _authorization(request), _params(request), kind)
        return Response(content, media_type=MEDIA)

    async def reading(identity: str, request: Request):
        _, content = await database(_rendered, service.read, _authorization(request), _params(request), kind, identity)
        return Response(content, media_type=MEDIA)

    # Writes follow Scim.body, which already accepted the credential before the writer is requested.
    async def creating(request: Request):
        body = await service.body(request)
        result, content = await database(_rendered, service.write, _authorization(request), _params(request), kind,
                                         'POST', body, admitted=True)
        return Response(content, status_code=201, media_type=MEDIA, headers={'Location': result['meta']['location']})

    async def updating(identity: str, request: Request):
        body = await service.body(request)
        result, content = await database(_rendered, service.write, _authorization(request), _params(request), kind,
                                         request.method, body, identity, admitted=True)
        if result is None:  # A Group PATCH that asked for no attributes (RFC 7644 section 3.5.2).
            return Response(status_code=204)
        return Response(content, media_type=MEDIA)

    async def deleting(identity: str, request: Request):
        await database(service.delete, _authorization(request), kind, identity)
        return Response(status_code=204)

    # Explicit routes keep the accepted resource names finite.
    for path, endpoint, methods in [(collection, listing, ['GET']), (collection, creating, ['POST']),
                                    (collection + '/{identity}', reading, ['GET']),
                                    (collection + '/{identity}', updating, ['PUT', 'PATCH']),
                                    (collection + '/{identity}', deleting, ['DELETE'])]:
        router.add_api_route(path, endpoint, methods=methods, name='scim_' + kind.lower() + '_' + endpoint.__name__)

