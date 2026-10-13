"""SCIM 2.0 provisioning for the existing workspace, without an authentication protocol.

The supported schema/filter/PATCH subset is deliberately explicit. Provisioning
does not create login sessions or replace verified Google/Access identities.
Deleted resources retain an inactive email tombstone to invalidate old sessions.
"""
import hashlib
import hmac
import json
import re
import secrets
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from .database import INTEGRITY_ERRORS
from .db import now

CORE = 'urn:ietf:params:scim:schemas:core:2.0:'
API = 'urn:ietf:params:scim:api:messages:2.0:'
MEDIA = 'application/scim+json'
MAX_RESULTS = 100
MAX_MEMBERS = 10000
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
USER_FIELDS = {'userName', 'externalId', 'active', 'displayName', 'name', 'emails',
               'title', 'userType', 'nickName', 'preferredLanguage', 'locale', 'timezone', 'profileUrl'}
GROUP_FIELDS = {'displayName', 'externalId', 'members'}
READ_ONLY = {'id', 'meta', 'groups'}


def active_for_email_in(conn, email):
    """Unmanaged people keep existing access; deprovisioned emails fail closed."""
    if not email or 'scim_users' not in conn.table_names():
        return True
    row = conn.execute("SELECT active,deleted_at FROM scim_users WHERE user_name=? ORDER BY (deleted_at='') DESC,updated_at DESC LIMIT 1",
                       (email.strip().lower(),)).fetchone()
    return not row or bool(row['active'] and not row['deleted_at'])


def active_for_actor_in(conn, actor_id):
    if not actor_id or 'scim_users' not in conn.table_names():
        return True
    rows = conn.execute('''SELECT source.kind,source.email,linked.email AS linked_email FROM users source
        LEFT JOIN users linked ON linked.id=source.linked_user_id WHERE source.id=?''', (actor_id,)).fetchall()
    if (any(row['kind'] == 'slack' and not row['email'] and not row['linked_email'] for row in rows)
            and conn.execute('SELECT 1 FROM scim_users LIMIT 1').fetchone()):
        return False
    return all(active_for_email_in(conn, row['email']) and active_for_email_in(conn, row['linked_email']) for row in rows)


def require_active_actor(store, actor_id):
    with store.connect() as conn:
        if not active_for_actor_in(conn, actor_id):
            raise HTTPException(403, 'This workspace account has been deactivated.')


class ScimError(Exception):
    def __init__(self, status, detail, kind=''):
        self.status, self.detail, self.kind = status, detail, kind


def error_response(error):
    body = {'schemas': [API + 'Error'], 'status': str(error.status), 'detail': error.detail}
    if error.kind:
        body['scimType'] = error.kind
    return JSONResponse(body, status_code=error.status, media_type=MEDIA,
                        headers={'Cache-Control': 'no-store', **({'WWW-Authenticate': 'Bearer'} if error.status == 401 else {})})


class ScimRoute(APIRoute):
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
            except INTEGRITY_ERRORS:
                return error_response(ScimError(409, 'A resource with this unique identity already exists.', 'uniqueness'))
        return scim_handler


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    label: str = Field(min_length=1, max_length=100)


def value_text(value, field, *, required=False, maximum=1000):
    if value is None and not required:
        return ''
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ScimError(400, f'{field} must be a valid string.', 'invalidValue')
    return value.strip()


def document(body, kind):
    if not isinstance(body, dict):
        raise ScimError(400, 'The request body must be a JSON object.', 'invalidSyntax')
    schemas = body.get('schemas', [CORE + kind])
    if not isinstance(schemas, list) or schemas != [CORE + kind]:
        raise ScimError(400, 'Only the advertised core resource schema is supported.', 'invalidValue')
    allowed = USER_FIELDS if kind == 'User' else GROUP_FIELDS
    unknown = set(body) - allowed - READ_ONLY - {'schemas'}
    if unknown:
        raise ScimError(400, 'The request contains unsupported attributes.', 'invalidValue')
    return {key: value for key, value in body.items() if key in allowed}


def validate_user(body):
    body = document(body, 'User')
    email = value_text(body.get('userName'), 'userName', required=True, maximum=254).lower()
    if not EMAIL.fullmatch(email):
        raise ScimError(400, 'userName must be a work email address.', 'invalidValue')
    active = body.get('active', True)
    if type(active) is not bool:
        raise ScimError(400, 'active must be a boolean.', 'invalidValue')
    result = {'userName': email, 'active': active}
    for field in USER_FIELDS - {'userName', 'active', 'name', 'emails'}:
        if field in body:
            result[field] = value_text(body[field], field, maximum=1000)
    if 'name' in body:
        name = body['name']
        if not isinstance(name, dict) or set(name) - {'formatted', 'givenName', 'familyName', 'middleName', 'honorificPrefix', 'honorificSuffix'}:
            raise ScimError(400, 'name contains unsupported attributes.', 'invalidValue')
        result['name'] = {key: value_text(value, 'name.' + key) for key, value in name.items()}
    if 'emails' in body:
        if not isinstance(body['emails'], list) or len(body['emails']) > 20:
            raise ScimError(400, 'emails must be an array with at most 20 entries.', 'invalidValue')
        result['emails'] = []
        for item in body['emails']:
            if not isinstance(item, dict) or set(item) - {'value', 'type', 'primary', 'display'}:
                raise ScimError(400, 'emails contains unsupported attributes.', 'invalidValue')
            entry = {key: value_text(value, 'emails.' + key, required=key == 'value', maximum=254)
                     for key, value in item.items() if key != 'primary'}
            if 'value' not in entry or not EMAIL.fullmatch(entry['value'].lower()):
                raise ScimError(400, 'Each email requires a valid value.', 'invalidValue')
            if 'primary' in item:
                if type(item['primary']) is not bool:
                    raise ScimError(400, 'emails.primary must be a boolean.', 'invalidValue')
                entry['primary'] = item['primary']
            result['emails'].append(entry)
        if sum(item.get('primary', False) for item in result['emails']) > 1:
            raise ScimError(400, 'Only one email can be primary.', 'invalidValue')
    return result


def normalize_path(path, kind):
    path = value_text(path, 'path', required=True, maximum=2000)
    if path.startswith(CORE + kind + ':'):
        path = path[len(CORE + kind + ':'):]
    return path


def patch_document(original, body, kind):
    if not isinstance(body, dict) or set(body) - {'schemas', 'Operations'} or body.get('schemas') != [API + 'PatchOp']:
        raise ScimError(400, 'Use the SCIM PatchOp schema and Operations array.', 'invalidSyntax')
    operations = body.get('Operations')
    if not isinstance(operations, list) or not operations or len(operations) > 100:
        raise ScimError(400, 'Operations must contain between 1 and 100 operations.', 'invalidSyntax')
    result = json.loads(json.dumps(original))
    result.pop('schemas', None)
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) - {'op', 'path', 'value'}:
            raise ScimError(400, 'Invalid PATCH operation.', 'invalidSyntax')
        op = operation.get('op', '')
        if not isinstance(op, str) or op.lower() not in {'add', 'replace', 'remove'}:
            raise ScimError(400, 'Unsupported PATCH operation.', 'invalidSyntax')
        op = op.lower()
        if op != 'remove' and 'value' not in operation:
            raise ScimError(400, 'PATCH add and replace require a value.', 'invalidValue')
        path = normalize_path(operation['path'], kind) if operation.get('path') else ''
        if not path:
            value = operation.get('value')
            if op == 'remove' or not isinstance(value, dict):
                raise ScimError(400, 'A path is required for remove; no-path values must be objects.', 'invalidPath')
            for key, item in value.items():
                if key in READ_ONLY:
                    raise ScimError(400, 'This attribute is read-only.', 'mutability')
                if key not in (USER_FIELDS if kind == 'User' else GROUP_FIELDS):
                    raise ScimError(400, 'Unsupported PATCH attribute.', 'invalidPath')
                if kind == 'Group' and key == 'members' and op == 'add':
                    if not isinstance(item, list):
                        raise ScimError(400, 'members must be an array.', 'invalidValue')
                    result[key] = result.get(key, []) + item
                else:
                    result[key] = item
            continue
        member = re.fullmatch(r'members\[value eq ("(?:[^"\\]|\\.)*")\]', path, re.I)
        if member and kind == 'Group':
            if op != 'remove':
                raise ScimError(400, 'Filtered membership paths support remove only.', 'invalidPath')
            identity = json.loads(member[1])
            before = result.get('members', [])
            result['members'] = [item for item in before if item.get('value') != identity]
            if len(before) == len(result['members']):
                raise ScimError(400, 'The member path did not match a resource.', 'noTarget')
            continue
        if path in READ_ONLY:
            raise ScimError(400, 'This attribute is read-only.', 'mutability')
        if kind == 'User' and path.startswith('name.') and path.split('.')[1] in {'formatted', 'givenName', 'familyName', 'middleName', 'honorificPrefix', 'honorificSuffix'}:
            name = result.setdefault('name', {})
            field = path.split('.')[1]
            if op == 'remove':
                if field not in name:
                    raise ScimError(400, 'The attribute does not exist.', 'noTarget')
                del name[field]
            else:
                name[field] = operation['value']
            continue
        if path not in (USER_FIELDS if kind == 'User' else GROUP_FIELDS):
            raise ScimError(400, 'Unsupported PATCH path.', 'invalidPath')
        if op == 'remove':
            if path in {'userName', 'displayName'} and (kind == 'Group' or path == 'userName'):
                raise ScimError(400, 'A required attribute cannot be removed.', 'mutability')
            if path not in result:
                raise ScimError(400, 'The attribute does not exist.', 'noTarget')
            result.pop(path)
        elif kind == 'Group' and path == 'members' and op == 'add':
            members = operation['value']
            if not isinstance(members, list):
                raise ScimError(400, 'members must be an array.', 'invalidValue')
            result['members'] = result.get('members', []) + members
        else:
            result[path] = operation['value']
    return result


class Scim:
    def __init__(self, store, security, governance=None):
        self.store, self.security = store, security
        self.governance = getattr(governance, 'enterprise', governance)
        if store.schema_updates:
            initialize_schema(store)

    @property
    def base_url(self):
        return self.security.origin + '/scim/v2'

    def authenticate_in(self, conn, request):
        auth = request.headers.get('authorization', '')
        match = re.fullmatch(r'Bearer (moyai_scim_([0-9a-f]{32})\.[A-Za-z0-9_-]{43})', auth, re.I)
        row = conn.execute('SELECT * FROM scim_tokens WHERE id=? AND revoked_at=\'\'',
                           (match[2],)).fetchone() if match else None
        if not row or not hmac.compare_digest(row['token_hash'], hashlib.sha256(match[1].encode()).hexdigest()):
            raise ScimError(401, 'A valid provisioning bearer credential is required.')
        return row['id']

    def guard_admins_in(self, conn):
        if self.governance is not None:
            self.governance.guard_admins_in(conn)
        elif self.security.user_roles is not None:
            roles = self.security.user_roles
            if not any(active_for_email_in(conn, email) for email in roles.admins_in(conn)) and roles.settings.google_domains():
                raise ScimError(409, 'Keep at least one active workspace administrator.')

    def audit_in(self, conn, actor, action, kind, identity):
        conn.execute('INSERT INTO scim_audit(id,actor,action,resource_type,resource_id,created_at) VALUES(?,?,?,?,?,?)',
                     (uuid4().hex, actor, action, kind, identity, now()))

    def resource_in(self, conn, kind, identity):
        table = 'scim_users' if kind == 'User' else 'scim_groups'
        row = conn.execute(f'SELECT * FROM {table} WHERE id=? AND deleted_at=\'\'', (identity,)).fetchone()
        if not row:
            raise ScimError(404, 'The requested resource does not exist.')
        row = dict(row)
        result = json.loads(row['profile']) if kind == 'User' else {'displayName': row['display_name']}
        result.update(schemas=[CORE + kind], id=row['id'])
        if row['external_id']:
            result['externalId'] = row['external_id']
        if kind == 'User':
            result.update(userName=row['user_name'], active=bool(row['active']))
            result['groups'] = [{'value': group['id'], 'display': group['display_name'], 'type': 'direct',
                                 '$ref': self.base_url + '/Groups/' + group['id']}
                                for group in conn.execute('''SELECT g.id,g.display_name FROM scim_groups g
                                    JOIN scim_group_members m ON m.group_id=g.id WHERE m.user_id=? AND g.deleted_at='' ORDER BY g.id''', (identity,))]
        else:
            result['members'] = [{'value': user['id'], 'display': user['user_name'], 'type': 'User',
                                  '$ref': self.base_url + '/Users/' + user['id']}
                                 for user in conn.execute('''SELECT u.id,u.user_name FROM scim_users u
                                     JOIN scim_group_members m ON m.user_id=u.id WHERE m.group_id=? AND u.deleted_at='' ORDER BY u.id''', (identity,))]
        result['meta'] = {'resourceType': kind, 'created': row['created_at'], 'lastModified': row['updated_at'],
                          'location': self.base_url + '/' + kind + 's/' + identity}
        return result

    def write_in(self, conn, kind, body, identity=None):
        stamp = now()
        current = self.resource_in(conn, kind, identity) if identity else None
        identity = identity or uuid4().hex
        body = validate_user(body) if kind == 'User' else document(body, kind)
        external = value_text(body.get('externalId'), 'externalId', maximum=1000)
        if external and conn.execute(f'SELECT 1 FROM scim_{"users" if kind == "User" else "groups"} WHERE external_id=? AND deleted_at=\'\' AND id!=?',
                                     (external, identity)).fetchone():
            raise ScimError(409, 'externalId must be unique for this resource type.', 'uniqueness')
        if kind == 'User':
            # Renaming would leave an old verified cookie ungoverned. Identity
            # migrations need an explicit account-linking workflow instead.
            if current and current['userName'] != body['userName']:
                raise ScimError(400, 'userName cannot be changed; deactivate the old identity and provision a new one.', 'mutability')
            profile = {key: value for key, value in body.items() if key not in {'externalId', 'userName', 'active'}}
            conn.execute('''INSERT INTO scim_users(id,external_id,user_name,profile,active,deleted_at,created_at,updated_at,revision)
                VALUES(?,?,?,?,?,'',?,?,1) ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,
                profile=excluded.profile,active=excluded.active,updated_at=excluded.updated_at,revision=scim_users.revision+1''',
                         (identity, external, body['userName'], json.dumps(profile), int(body['active']), stamp, stamp))
        else:
            display = value_text(body.get('displayName'), 'displayName', required=True, maximum=254)
            members = body.get('members', [])
            if not isinstance(members, list) or len(members) > MAX_MEMBERS:
                raise ScimError(400, f'members must be an array with at most {MAX_MEMBERS} entries.', 'invalidValue')
            selected = set()
            for member in members:
                if not isinstance(member, dict) or set(member) - {'value', '$ref', 'display', 'type'} or member.get('type', 'User') != 'User':
                    raise ScimError(400, 'Only User members are supported.', 'invalidValue')
                user = value_text(member.get('value'), 'members.value', required=True, maximum=100)
                if not conn.execute("SELECT 1 FROM scim_users WHERE id=? AND deleted_at=''", (user,)).fetchone():
                    raise ScimError(400, 'A member must reference an existing provisioned user.', 'invalidValue')
                selected.add(user)
            conn.execute('''INSERT INTO scim_groups(id,external_id,display_name,display_key,deleted_at,created_at,updated_at,revision)
                VALUES(?,?,?,?,'',?,?,1) ON CONFLICT(id) DO UPDATE SET external_id=excluded.external_id,
                display_name=excluded.display_name,display_key=excluded.display_key,updated_at=excluded.updated_at,revision=scim_groups.revision+1''',
                         (identity, external, display, display.casefold(), stamp, stamp))
            conn.execute('DELETE FROM scim_group_members WHERE group_id=?', (identity,))
            for user in sorted(selected):
                conn.execute('INSERT INTO scim_group_members(group_id,user_id) VALUES(?,?)', (identity, user))
        self.guard_admins_in(conn)
        return self.resource_in(conn, kind, identity)

    def list_in(self, conn, request, kind):
        allowed = {'filter', 'startIndex', 'count'}
        if set(request.query_params) - allowed:
            raise ScimError(400, 'Only filter, startIndex, and count query parameters are supported.', 'invalidValue')
        try:
            start = max(1, int(request.query_params.get('startIndex', '1')))
            count = min(MAX_RESULTS, max(0, int(request.query_params.get('count', str(MAX_RESULTS)))))
        except (TypeError, ValueError):
            raise ScimError(400, 'startIndex and count must be integers.', 'invalidValue') from None
        table = 'scim_users' if kind == 'User' else 'scim_groups'
        predicate, args = "deleted_at=''", []
        expression = request.query_params.get('filter', '')
        if expression:
            match = re.fullmatch(r'\s*([a-zA-Z]+)\s+eq\s+("(?:[^"\\]|\\.)*"|true|false)\s*', expression, re.I)
            fields = {'id': 'id', 'externalid': 'external_id',
                      **({'username': 'user_name', 'active': 'active'} if kind == 'User' else {'displayname': 'display_key'})}
            if not match or match[1].lower() not in fields:
                raise ScimError(400, 'Only eq on id, externalId, userName/active (Users), or displayName (Groups) is supported.', 'invalidFilter')
            try:
                value = json.loads(match[2].lower() if match[2].lower() in {'true', 'false'} else match[2])
            except ValueError:
                raise ScimError(400, 'Invalid filter literal.', 'invalidFilter') from None
            field = match[1].lower()
            if (field == 'active') != isinstance(value, bool):
                raise ScimError(400, 'The filter value has the wrong type.', 'invalidFilter')
            if field == 'username':
                value = value.lower()
            elif field == 'displayname':
                value = value.casefold()
            predicate += ' AND ' + fields[field] + '=?'
            args.append(int(value) if isinstance(value, bool) else value)
        total = conn.execute(f'SELECT COUNT(*) AS n FROM {table} WHERE {predicate}', args).fetchone()['n']
        ids = conn.execute(f'SELECT id FROM {table} WHERE {predicate} ORDER BY id LIMIT ? OFFSET ?',
                           [*args, count, start - 1]).fetchall()
        resources = [self.resource_in(conn, kind, row['id']) for row in ids]
        return {'schemas': [API + 'ListResponse'], 'totalResults': total, 'startIndex': start,
                'itemsPerPage': len(resources), 'Resources': resources}

    def routes(self):
        router = APIRouter(prefix='/scim/v2', route_class=ScimRoute)

        @router.get('/ServiceProviderConfig')
        async def config(request: Request):
            with self.store.connect() as conn:
                self.authenticate_in(conn, request)
            return JSONResponse({'schemas': [CORE + 'ServiceProviderConfig'],
                'patch': {'supported': True}, 'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
                'filter': {'supported': True, 'maxResults': MAX_RESULTS}, 'changePassword': {'supported': False},
                'sort': {'supported': False}, 'etag': {'supported': False},
                'authenticationSchemes': [{'type': 'oauthbearertoken', 'name': 'Provisioning bearer credential',
                    'description': 'Administrator-created random bearer credential, stored as a SHA-256 hash.',
                    'primary': True}],
                'documentationUri': 'https://www.rfc-editor.org/rfc/rfc7644'}, media_type=MEDIA)

        @router.get('/ResourceTypes')
        @router.get('/ResourceTypes/{identity}')
        async def resource_types(request: Request, identity: str = ''):
            with self.store.connect() as conn:
                self.authenticate_in(conn, request)
            resources = [{'schemas': [CORE + 'ResourceType'], 'id': kind, 'name': kind,
                          'endpoint': '/' + kind + 's', 'schema': CORE + kind, 'schemaExtensions': []}
                         for kind in ('User', 'Group')]
            return self.discovery(resources, identity)

        @router.get('/Schemas')
        @router.get('/Schemas/{identity:path}')
        async def schemas(request: Request, identity: str = ''):
            with self.store.connect() as conn:
                self.authenticate_in(conn, request)
            resources = [self.schema(kind) for kind in ('User', 'Group')]
            return self.discovery(resources, identity)

        # Add routes explicitly, keeping the accepted resource names finite.
        for kind in ('User', 'Group'):
            self.resource_routes(router, kind)
        return router

    @staticmethod
    def discovery(resources, identity):
        if identity:
            resources = [item for item in resources if item['id'] == identity]
            if not resources:
                raise ScimError(404, 'The requested resource does not exist.')
            return JSONResponse(resources[0], media_type=MEDIA)
        return JSONResponse({'schemas': [API + 'ListResponse'], 'totalResults': len(resources),
                             'startIndex': 1, 'itemsPerPage': len(resources), 'Resources': resources}, media_type=MEDIA)

    @staticmethod
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
                           attribute('name', 'complex', sub=[attribute(name) for name in ('formatted', 'givenName', 'familyName', 'middleName', 'honorificPrefix', 'honorificSuffix')]),
                           attribute('emails', 'complex', multi=True, sub=[attribute('value'), attribute('type'), attribute('display'), attribute('primary', 'boolean')])]
            attributes += [attribute(name) for name in sorted(USER_FIELDS - {'userName', 'externalId', 'active', 'name', 'emails'})]
            attributes += [attribute('groups', 'complex', multi=True, readonly=True,
                                     sub=[attribute('value', readonly=True), attribute('$ref', 'reference', readonly=True), attribute('display', readonly=True), attribute('type', readonly=True)])]
        else:
            attributes += [attribute('displayName', required=True), attribute('members', 'complex', multi=True,
                           sub=[attribute('value'), attribute('$ref', 'reference'), attribute('display', readonly=True), attribute('type')])]
        if kind == 'User':
            next(item for item in attributes if item['name'] == 'userName')['mutability'] = 'immutable'
        return {'schemas': [CORE + 'Schema'], 'id': CORE + kind, 'name': kind,
                'description': 'Moyai supported provisioning attributes.', 'attributes': attributes}

    async def body(self, request):
        # Fail unauthenticated calls before parsing client-supplied content, then
        # recheck the credential inside the transaction that changes resources.
        with self.store.connect() as conn:
            self.authenticate_in(conn, request)
        if request.headers.get('content-type', '').split(';')[0].strip().lower() not in {MEDIA, 'application/json'}:
            raise ScimError(415, 'Use application/scim+json or application/json.')
        try:
            raw = await request.body()
            if len(raw) > 2 * 1024 * 1024:
                raise ScimError(413, 'The provisioning request is too large.')
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise ScimError(400, 'The request body must be valid JSON.', 'invalidSyntax') from None

    def resource_routes(self, router, kind):
        collection = '/' + kind + 's'

        async def listing(request: Request):
            with self.store.connect() as conn:
                conn.begin_read()
                self.authenticate_in(conn, request)
                result = self.list_in(conn, request, kind)
            return JSONResponse(result, media_type=MEDIA)

        async def reading(identity: str, request: Request):
            with self.store.connect() as conn:
                conn.begin_read()
                self.authenticate_in(conn, request)
                result = self.resource_in(conn, kind, identity)
            return JSONResponse(result, media_type=MEDIA)

        async def creating(request: Request):
            body = await self.body(request)
            with self.store.connect() as conn:
                conn.begin_write()
                actor = self.authenticate_in(conn, request)
                result = self.write_in(conn, kind, body)
                self.audit_in(conn, actor, 'create', kind, result['id'])
            return JSONResponse(result, status_code=201, media_type=MEDIA, headers={'Location': result['meta']['location']})

        async def updating(identity: str, request: Request):
            body = await self.body(request)
            with self.store.connect() as conn:
                conn.begin_write()
                actor = self.authenticate_in(conn, request)
                current = self.resource_in(conn, kind, identity)
                if request.method == 'PATCH':
                    current = {key: value for key, value in current.items() if key in (USER_FIELDS if kind == 'User' else GROUP_FIELDS)}
                    body = patch_document(current, body, kind)
                result = self.write_in(conn, kind, body, identity)
                self.audit_in(conn, actor, request.method.lower(), kind, identity)
            return JSONResponse(result, media_type=MEDIA)

        async def deleting(identity: str, request: Request):
            with self.store.connect() as conn:
                conn.begin_write()
                actor = self.authenticate_in(conn, request)
                self.resource_in(conn, kind, identity)
                stamp = now()
                if kind == 'User':
                    conn.execute('UPDATE scim_users SET active=0,deleted_at=?,updated_at=?,revision=revision+1 WHERE id=?', (stamp, stamp, identity))
                    conn.execute('DELETE FROM scim_group_members WHERE user_id=?', (identity,))
                else:
                    conn.execute('UPDATE scim_groups SET deleted_at=?,updated_at=?,revision=revision+1 WHERE id=?', (stamp, stamp, identity))
                    conn.execute('DELETE FROM scim_group_members WHERE group_id=?', (identity,))
                self.guard_admins_in(conn)
                self.audit_in(conn, actor, 'delete', kind, identity)
            return Response(status_code=204)

        for path, endpoint, methods in [(collection, listing, ['GET']), (collection, creating, ['POST']),
                                        (collection + '/{identity}', reading, ['GET']),
                                        (collection + '/{identity}', updating, ['PUT', 'PATCH']),
                                        (collection + '/{identity}', deleting, ['DELETE'])]:
            router.add_api_route(path, endpoint, methods=methods, name='scim_' + kind.lower() + '_' + endpoint.__name__)

    def admin_routes(self):
        router = APIRouter()

        @router.get('/api/admin/scim')
        async def directory(request: Request):
            self.security.require(request, admin=True, permission='scim.manage')
            with self.store.connect() as conn:
                conn.begin_read()
                tokens = [dict(row) for row in conn.execute('SELECT id,label,prefix,created_at,revoked_at FROM scim_tokens ORDER BY created_at DESC')]
                users = [self.resource_in(conn, 'User', row['id']) for row in conn.execute("SELECT id FROM scim_users WHERE deleted_at='' ORDER BY user_name")]
                groups = [self.resource_in(conn, 'Group', row['id']) for row in conn.execute("SELECT id FROM scim_groups WHERE deleted_at='' ORDER BY display_key")]
                activity = [dict(row) for row in conn.execute('SELECT * FROM scim_audit ORDER BY created_at DESC,id DESC LIMIT 50')]
            return {'base_url': self.base_url, 'tokens': tokens, 'users': users, 'groups': groups, 'activity': activity,
                    'supported_filters': {'Users': ['userName eq', 'externalId eq', 'id eq', 'active eq'],
                                          'Groups': ['displayName eq', 'externalId eq', 'id eq']}}

        @router.post('/api/admin/scim/tokens')
        async def create_token(body: TokenCreate, request: Request):
            self.security.require(request, admin=True, mutation=True, permission='scim.manage')
            identity = uuid4().hex
            token = 'moyai_scim_' + identity + '.' + secrets.token_urlsafe(32)
            actor = self.security.session_info(request)
            label = actor.get('identity', {}).get('email') or actor.get('method', 'admin')
            with self.store.connect() as conn:
                conn.begin_write()
                if self.governance is not None:
                    self.governance.authorize_in(conn, actor, 'scim.manage')
                conn.execute('INSERT INTO scim_tokens(id,label,token_hash,prefix,created_at,revoked_at) VALUES(?,?,?,?,?,\'\')',
                             (identity, body.label, hashlib.sha256(token.encode()).hexdigest(), token[:19], now()))
                self.audit_in(conn, label, 'create credential', 'Credential', identity)
            return JSONResponse({'id': identity, 'label': body.label, 'token': token, 'base_url': self.base_url},
                                headers={'Cache-Control': 'no-store'})

        @router.delete('/api/admin/scim/tokens/{identity}')
        async def revoke_token(identity: str, request: Request):
            self.security.require(request, admin=True, mutation=True, permission='scim.manage')
            actor = self.security.session_info(request)
            label = actor.get('identity', {}).get('email') or actor.get('method', 'admin')
            with self.store.connect() as conn:
                conn.begin_write()
                if self.governance is not None:
                    self.governance.authorize_in(conn, actor, 'scim.manage')
                row = conn.execute('SELECT revoked_at FROM scim_tokens WHERE id=?', (identity,)).fetchone()
                if not row:
                    raise HTTPException(404, 'Provisioning credential not found.')
                if not row['revoked_at']:
                    conn.execute('UPDATE scim_tokens SET revoked_at=? WHERE id=?', (now(), identity))
                    self.audit_in(conn, label, 'revoke credential', 'Credential', identity)
            return Response(status_code=204)

        return router


def initialize_schema(store):
    store.execute('''CREATE TABLE IF NOT EXISTS scim_tokens (
        id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT NOT NULL,
        prefix TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT NOT NULL DEFAULT '')''')
    store.execute('''CREATE TABLE IF NOT EXISTS scim_users (
        id TEXT PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', user_name TEXT NOT NULL,
        profile TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), deleted_at TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revision INTEGER NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS scim_groups (
        id TEXT PRIMARY KEY, external_id TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL,
        display_key TEXT NOT NULL, deleted_at TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revision INTEGER NOT NULL)''')
    store.execute('''CREATE TABLE IF NOT EXISTS scim_group_members (
        group_id TEXT NOT NULL REFERENCES scim_groups(id), user_id TEXT NOT NULL REFERENCES scim_users(id),
        PRIMARY KEY(group_id,user_id))''')
    store.execute('''CREATE TABLE IF NOT EXISTS scim_audit (
        id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL, created_at TEXT NOT NULL)''')
    store.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_users_external ON scim_users(external_id) WHERE external_id!='' AND deleted_at=''")
    store.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_users_name ON scim_users(user_name) WHERE deleted_at=''")
    store.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_external ON scim_groups(external_id) WHERE external_id!='' AND deleted_at=''")
    store.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_display ON scim_groups(display_key) WHERE deleted_at=''")
