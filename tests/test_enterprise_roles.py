"""Permission catalog, native tool permissions and custom-role rules on SQLite or --postgres-backend."""
import ast
import inspect
import json
import os
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from app import enterprise_roles
from app.config import Settings
from app.db import Store
from app.enterprise_roles import (
    ACCESS_QUERIES,
    ADMIN_ONLY,
    AMPLIFY,
    DEACTIVATED,
    FORBIDDEN,
    HELD_GRANT,
    HELD_PERSON,
    HELD_ROLE,
    OWN_GROUP,
    SELF,
    STALE,
    GovernanceActor,
    GovernanceConflict,
    GovernanceError,
    GovernanceForbidden,
    GovernanceInvalid,
    GovernanceNotFound,
    GroupRoleChange,
    RoleAssignment,
    RoleCreate,
    RoleUpdate,
    canonical_fetch,
    directory_fetch,
    resolve_access,
    snapshot_fetch,
)
from app.permissions import (
    BUILTIN_PERMISSIONS,
    DEFAULT_TOOL_PERMISSION,
    MEMBER_PERMISSIONS,
    PERMISSIONS,
    TOOL_PERMISSIONS,
    catalog,
    connector_tool,
    route_permission,
    tool_permission,
)
from app.scim import CORE, Scim
from app.user_roles import UserRoles
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
ALL = BUILTIN_PERMISSIONS['admin']
READER = ['sessions.read', 'workspace.read']


def person(email, role='member', permissions=None, **extra):
    return GovernanceActor(id='google:' + email.split('@')[0], email=email, builtin_role=role,
                           permissions=permissions, kind='individual', **extra)


OWNER = person('owner@example.com', 'admin')


@pytest.fixture
def governance(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    store = Store(tmp_path)
    try:
        roles = UserRoles(store, settings)
        scim = Scim(store, roles, base_url='http://localhost:8787/scim/v2')
        _, token = scim.create_token('Directory', OWNER)
        yield SimpleNamespace(store=store, settings=settings, roles=roles, enterprise=roles.enterprise,
                              scim=scim, header='Bearer ' + token)
    finally:
        store.close()


def role(service, identity='reader', permissions=READER, actor=OWNER):
    return service.enterprise.create(RoleCreate(id=identity, name=identity.title(), permissions=permissions), actor)


def assign(service, email, role_id, revision=0, actor=OWNER, role_revision=None):
    return service.enterprise.assign(RoleAssignment(email=email, role_id=role_id, revision=revision,
                                                    role_revision=role_revision), actor)


def provision(service, email, *, active=True):
    return service.scim.write(service.header, {}, 'User', 'POST',
                              {'schemas': [CORE + 'User'], 'userName': email, 'active': active})['id']


def directory_group(service, name, members=()):
    return service.scim.write(service.header, {}, 'Group', 'POST',
                              {'displayName': name, 'members': [{'value': member} for member in members]})['id']


def access(service, email):
    with service.store.connect() as conn:
        return service.roles.access_in(conn, email)


def denied(error, status, detail):
    assert error.value.status_code == status and error.value.detail == detail, (error.value.status_code, error.value.detail)


def events(service, action=None):
    rows = service.store.rows('SELECT action,actor,resource_type,resource_id,details FROM governance_audit_events ORDER BY created_at,id')
    return [row for row in rows if action is None or row['action'] == action]


def test_catalog_lists_every_permission_once_with_labels_and_groups():
    entries = catalog()
    assert [entry['id'] for entry in entries].count('roles.manage') == 1
    assert {entry['id'] for entry in entries} == set(PERMISSIONS) and len(entries) == len(PERMISSIONS)
    assert all(entry['label'] and entry['group'] and entry['description'] == PERMISSIONS[entry['id']] for entry in entries)
    assert BUILTIN_PERMISSIONS['admin'] == frozenset(PERMISSIONS) and MEMBER_PERMISSIONS < ALL
    # The default member grant is spelled out so any widening reads as a reviewable diff.
    assert sorted(MEMBER_PERMISSIONS) == [
        'automations.manage', 'automations.read', 'connections.read', 'connections.write', 'credentials.manage',
        'credentials.read', 'environments.read', 'memory.manage', 'memory.read', 'sessions.create', 'sessions.manage',
        'sessions.read', 'skills.manage', 'skills.read', 'spend.personal', 'workspace.read']
    assert len(PERMISSIONS) == 28


def tool_names_of(capability):
    from pydantic_ai.toolsets import AbstractToolset

    found = set()

    def names(toolset):
        if isinstance(getattr(toolset, 'tools', None), dict):
            found.update(toolset.tools)
        for inner in (getattr(toolset, 'wrapped', None), *getattr(toolset, 'toolsets', ())):
            if isinstance(inner, AbstractToolset):
                names(inner)

    def visit(item):
        toolset = item.get_toolset() if hasattr(item, 'get_toolset') else item
        if isinstance(toolset, AbstractToolset):
            names(toolset)
        return item

    if hasattr(capability, 'visit_and_replace'):
        capability.visit_and_replace(visit)
    else:
        visit(capability)
    return found


def test_every_native_tool_has_an_explicit_permission():
    import warnings

    from pydantic_ai_harness import Coder
    from pydantic_ai_harness.ask_user import AskUser
    from pydantic_ai_harness.conversation_search import ConversationSearch
    from pydantic_ai_harness.memory import Memory
    from pydantic_ai_harness.planning import Planning

    from moyai import product_automation_tools, product_credential_tools, product_github_publication
    from moyai.artifacts import artifact_capability
    from moyai.browser import browser_capability
    from moyai.contracts import Grant
    from moyai.input_attachments import attachment_capability

    grant = Grant(id='a' * 36, kind='github', revision=1, credential='', read_only=False,
                  policy={'product': {'repository_id': 1}})
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        sources = [
            # make_agent's capabilities in native/src/moyai/agent.py, plus product tool capabilities.
            artifact_capability(None, None), browser_capability(None), attachment_capability(None, None),
            Coder(), Planning(enable_subtasks=True), AskUser(answerer=None), Memory(), ConversationSearch(None),
            product_credential_tools.CredentialTools(SimpleNamespace(enabled=False)),
            product_automation_tools.toolset(SimpleNamespace(credentials=object())),
            product_github_publication.toolset(SimpleNamespace(database=None), None, grant),
        ]
    exposed = set().union(*(tool_names_of(source) for source in sources))
    assert {'shell', 'delegate_task', 'credentials_run', 'automation_retire', 'create_pull_request'} <= exposed
    # The framework's deferred-capability loader serves saved and bundled skills.
    exposed.add('load_capability')
    assert exposed - set(TOOL_PERMISSIONS) == set()
    # Static net: any tool a native module registers must be explicit too.
    registered = set()
    for path in (ROOT / 'native/src/moyai').rglob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for item in node.decorator_list:
                    target = item.func if isinstance(item, ast.Call) else item
                    if isinstance(target, ast.Attribute) and target.attr == 'tool':
                        # A name= override is what the model sees and what policies govern.
                        named = next((keyword.value.value for keyword in getattr(item, 'keywords', ())
                                      if keyword.arg == 'name' and isinstance(keyword.value, ast.Constant)), None)
                        registered.add(named or node.name)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'Capability', 'Tool'}:
                arguments = [*node.args[:1]] if node.func.id == 'Tool' else [
                    *next((keyword.value.elts for keyword in node.keywords
                           if keyword.arg == 'tools' and isinstance(keyword.value, ast.List)), [])]
                for argument in arguments:
                    argument = argument.args[0] if isinstance(argument, ast.Call) and argument.args else argument
                    if isinstance(argument, ast.Name):
                        registered.add(argument.id)
    assert {'save_artifact', 'browser_open', 'automation_list', 'credentials_list', 'publication_status'} <= registered
    assert registered - set(TOOL_PERMISSIONS) == set()
    assert all(TOOL_PERMISSIONS[name] in PERMISSIONS and tool_permission(name) == TOOL_PERMISSIONS[name]
               for name in TOOL_PERMISSIONS)


def test_connector_tools_follow_the_canonical_read_write_catalog():
    from app.connectors import TOOLS
    for name, (provider, write, _, _) in TOOLS.items():
        expected = 'connections.write' if write else 'connections.read'
        assert tool_permission(name) == expected, name
        # Product toolsets strip the provider prefix, then connection_tools adds the grant prefix.
        prefixed = f'{provider}_0a1b2c3d_{name.removeprefix(provider + "_")}'
        assert connector_tool(prefixed) == (provider, name.removeprefix(provider + '_'))
        assert tool_permission(prefixed) == expected, prefixed
    assert tool_permission('github_0a1b2c3d_create_pull_request') == 'connections.write'
    assert tool_permission('github_0a1b2c3d_request_pull_request_write_access') == 'connections.write'
    assert tool_permission('github_0a1b2c3d_publication_status') == 'connections.read'
    # Shared repository tools are routed as `github_<operation>`, so app and Git
    # policies and connections.write govern them like the grant-prefixed names.
    assert connector_tool('github_checkout') == ('github', 'checkout')
    assert tool_permission('github_checkout') == 'connections.read'
    for operation in ('create_pull_request', 'publish_branch', 'open_pull_request', 'submit_review', 'create_stack'):
        assert connector_tool('github_' + operation) == ('github', operation)
        assert tool_permission('github_' + operation) == 'connections.write', operation
    assert tool_permission('github_get_file_contents', read_only=True) == 'connections.read'
    assert tool_permission('github_get_file_contents') == 'connections.write'
    # Provider tools outside the canonical catalog are writes unless their server-built definition is read-only.
    assert tool_permission('github_0a1b2c3d_get_file_contents') == 'connections.write'
    assert tool_permission('github_0a1b2c3d_get_file_contents', read_only=True) == 'connections.read'
    assert tool_permission('notion_0a1b2c3d_future_write', read_only=False) == 'connections.write'
    # Unknown names are session work, never "no check".
    for name in ('future_unknown_capability', 'github_', '', None, 7):
        assert tool_permission(name) == DEFAULT_TOOL_PERMISSION


@pytest.mark.parametrize(('method', 'path', 'permission'), [
    # A member's own Slack link is a personal credential; organization Slack is setup.
    ('GET', '/api/connections/slack/personal', 'credentials.read'),
    ('POST', '/api/connections/slack/personal/oauth', 'credentials.manage'),
    ('POST', '/api/connections/slack/personal/check', 'credentials.manage'),
    ('DELETE', '/api/connections/slack/personal', 'credentials.manage'),
    ('POST', '/api/connections/slack/oauth', 'connections.manage'),
    ('GET', '/oauth/slack/callback', None),  # Shared with organization Slack; each handler checks its own.
    # Historical search, folders and archives expose session content.
    ('GET', '/api/product/search', 'sessions.read'),
    ('GET', '/api/product/folders', 'sessions.read'),
    ('GET', '/api/runs/' + '0' * 32 + '/artifact', 'sessions.read'),
    # The limit listing's handler accepts spend.read or spend.manage.
    ('GET', '/api/admin/spend-limits', None),
    ('PUT', '/api/admin/spend-limits', 'spend.manage'),
    ('DELETE', '/api/admin/spend-limits/user:person@example.com', 'spend.manage'),
    ('DELETE', '/api/admin/spend-limits/group:' + 'e' * 32, 'spend.manage'),
    ('GET', '/api/admin/spend-limits/effective', None),
    ('GET', '/api/admin/spend', 'spend.read'),
    # A new session's policy previews admission; choosing a profile also needs security.manage.
    ('GET', '/api/security-policy/new-session', 'sessions.create'),
    # A person's own budget status, like their own spend report.
    ('GET', '/api/spend/status', 'spend.personal'),
    ('GET', '/api/spend', 'spend.personal'),
])
def test_route_permissions_follow_the_resource(method, path, permission):
    assert route_permission(SimpleNamespace(scope={'path': path}, method=method)) == permission


def canonical_read_engine(service):
    """A SQLAlchemy engine on the governance store and its quoted, qualified table names."""
    import sqlalchemy
    if service.store.database:
        schema = service.store.database.schema
        engine = sqlalchemy.create_engine('postgresql+psycopg://' + os.environ['MOYAI_TEST_POSTGRES_URL'].split('://', 1)[1])
        return engine, SimpleNamespace(_table=lambda name: f'"{schema}"."{name}"')
    return sqlalchemy.create_engine(f'sqlite:///{service.store.path}'), SimpleNamespace(
        _table=lambda name: f'"main"."{name}"')


def test_resolution_is_pure_and_matches_named_queries(governance):
    from moyai.product_governance import CanonicalRead
    service = governance
    role(service)
    role(service, 'operator', ['connections.manage', 'workspace.read'])
    assign(service, 'bob@example.com', 'reader')
    team = directory_group(service, 'Ops', [provision(service, 'bob@example.com')])
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='operator'), OWNER)
    with service.store.connect() as conn:
        canonical = resolve_access(canonical_fetch(conn), 'bob@example.com', 'member')
    assert canonical.permissions == {'sessions.read', 'workspace.read', 'connections.manage'}
    assert canonical.groups == ((team, 1, 'operator'),) and canonical.role_id == 'reader' and not canonical.default
    # The native adapter's form: CanonicalRead binds SQLAlchemy text() and qualified quoted tables.
    engine, identity = canonical_read_engine(service)
    try:
        with engine.connect() as session:
            read = CanonicalRead(session, identity)
            assert resolve_access(canonical_fetch(read), 'bob@example.com', 'member') == canonical
            assert resolve_access(snapshot_fetch(read, 'bob@example.com'), 'bob@example.com', 'member') == canonical
            assert resolve_access(snapshot_fetch(read, 'nobody@example.com'), 'nobody@example.com', 'member').default
    finally:
        engine.dispose()
    assert all('{' not in sql and ':' in sql for sql in ACCESS_QUERIES.values())


def test_snapshot_and_directory_reads_match_per_query_resolution(governance, monkeypatch):
    """One statement per person (native checks) and one batch (users page) keep resolve_access's results."""
    from moyai.product_governance import CanonicalRead
    service = governance
    role(service)
    role(service, 'operator', ['connections.manage', 'workspace.read'])
    role(service, 'auditor', ['spend.read'])
    role(service, 'retired', ['memory.read'])
    # A tombstone and a live row for one userName, with two grants.
    first = provision(service, 'ann@example.com')
    service.scim.delete(service.header, 'User', first)
    ann = provision(service, 'ann@example.com')
    ops, audit = directory_group(service, 'Ops', [ann]), directory_group(service, 'Audit', [ann])
    service.enterprise.set_group_role(ops, GroupRoleChange(role_id='operator'), OWNER)
    service.enterprise.set_group_role(audit, GroupRoleChange(role_id='auditor'), OWNER)
    assign(service, 'ann@example.com', 'reader')
    # An inactive member of a granted group, and an administrator in one.
    idle = provision(service, 'idle@example.com', active=False)
    owner = provision(service, 'owner@example.com')
    service.scim.write(service.header, {}, 'Group', 'PUT', {'displayName': 'Ops', 'members': [
        {'value': ann}, {'value': idle}, {'value': owner}]}, ops)
    # Archived, missing and built-in-named assigned roles, and a 'member' reset row.
    assign(service, 'old@example.com', 'retired')
    service.enterprise.archive('retired', 1, OWNER)
    stamp = '2026-01-01T00:00:00+00:00'
    for email, role_id in (('ghost@example.com', 'vanished'), ('named@example.com', 'admin')):
        service.store.execute('INSERT INTO enterprise_role_assignments VALUES(?,?,1,?,?)', (email, role_id, 'test', stamp))
    assign(service, 'reset@example.com', 'reader')
    assign(service, 'reset@example.com', 'member', revision=1)
    emails = ('ann@example.com', 'idle@example.com', 'owner@example.com', 'old@example.com', 'ghost@example.com',
              'named@example.com', 'reset@example.com', 'nobody@example.com')
    engine, identity = canonical_read_engine(service)
    try:
        with service.store.connect() as conn, engine.connect() as session:
            directory = directory_fetch(conn)
            read = CanonicalRead(session, identity)
            for email in emails:
                builtin = service.roles.role_in(conn, email)
                expected = resolve_access(canonical_fetch(conn), email, builtin)
                for fetch in (snapshot_fetch(conn, email), snapshot_fetch(read, email), directory):
                    assert resolve_access(fetch, email, builtin) == expected, email
            executed = statements(monkeypatch)
            fetch = snapshot_fetch(conn, 'ann@example.com')
            ann_state = resolve_access(fetch, 'ann@example.com', 'member')
            assert len(executed) == 1
            # It serves only this email's reads and its assigned role.
            for name, params in (('scim_user', {'email': 'idle@example.com'}), ('role', {'role_id': 'operator'}),
                                 ('users', {'email': 'ann@example.com'})):
                with pytest.raises(KeyError):
                    fetch(name, params)
    finally:
        engine.dispose()
    assert ann_state.groups == tuple(sorted(((audit, 1, 'auditor'), (ops, 1, 'operator'))))
    assert ann_state.permissions == {'sessions.read', 'workspace.read', 'connections.manage', 'spend.read'}
    assert ann_state.directory is not None and ann_state.directory[0] == ann
    assert access(service, 'idle@example.com').permissions == frozenset()
    assert access(service, 'owner@example.com').groups == () and access(service, 'ghost@example.com').permissions == frozenset()


def test_default_state_and_member_rows_never_change_governance(governance):
    service = governance
    plain = access(service, 'plain@example.com')
    assert plain.default and plain.permissions == MEMBER_PERMISSIONS and plain.authority_entry() is None
    assert plain.scim_active is None and plain.role_id is None and plain.groups == ()
    admin = access(service, 'owner@example.com')
    assert admin.default and admin.permissions == ALL and admin.authority_entry() is None
    # A built-in 'member' row equals no row for access: same permissions, still default (Slack and web
    # alike). Its revision still keeps an authority entry, so the reset never revalidates the pre-change version.
    role(service)
    assign(service, 'maya@example.com', 'reader')
    assign(service, 'maya@example.com', 'member', revision=1)
    reset = access(service, 'maya@example.com')
    assert reset.default and reset.role_id is None and reset.permissions == MEMBER_PERMISSIONS
    assert reset.assignment_revision == 2 and reset.authority_entry() == {
        'role_id': None, 'role_revision': 0, 'assignment_revision': 2, 'groups': [],
        'permissions': sorted(MEMBER_PERMISSIONS)}
    # Provisioned but otherwise unchanged people stay default, with no entry.
    provision(service, 'plain@example.com')
    provisioned = access(service, 'plain@example.com')
    assert provisioned.default and provisioned.scim_active is True and provisioned.authority_entry() is None


def test_custom_archived_group_and_deactivated_resolution(governance):
    service = governance
    role(service)
    role(service, 'operator', ['connections.manage', 'workspace.read'])
    role(service, 'subset', ['workspace.read'])
    assign(service, 'bob@example.com', 'reader')
    state = access(service, 'bob@example.com')
    assert state.permissions == set(READER) and state.role_name == 'Reader' and state.role_revision == 1
    assert state.authority_entry() == {'role_id': 'reader', 'role_revision': 1, 'assignment_revision': 1,
                                       'groups': [], 'permissions': READER}
    bob = provision(service, 'bob@example.com')
    team = directory_group(service, 'Ops', [bob])
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='operator'), OWNER)
    assert access(service, 'bob@example.com').permissions == {*READER, 'connections.manage'}
    # An archived direct role grants nothing (no member fallback); group grants still add.
    service.enterprise.archive('reader', 1, OWNER)
    assert access(service, 'bob@example.com').permissions == {'connections.manage', 'workspace.read'}
    # A subset group grant leaves a member's state default; a built-in admin never needs group grants.
    carol = provision(service, 'carol@example.com')
    owner = provision(service, 'owner@example.com')
    small = directory_group(service, 'Small', [carol, owner])
    service.enterprise.set_group_role(small, GroupRoleChange(role_id='subset'), OWNER)
    assert access(service, 'carol@example.com').default and access(service, 'carol@example.com').groups
    assert access(service, 'owner@example.com').permissions == ALL and access(service, 'owner@example.com').default
    # Deactivation and deletion remove every permission, even a built-in administrator's.
    service.scim.write(service.header, {}, 'User', 'PATCH', {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                       'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]}, bob)
    inactive = access(service, 'bob@example.com')
    assert inactive.scim_active is False and inactive.permissions == frozenset() and not inactive.default
    service.scim.delete(service.header, 'User', carol)
    assert access(service, 'carol@example.com').scim_active is False
    assert not access(service, 'carol@example.com').permissions
    provision(service, 'carol@example.com')
    assert access(service, 'carol@example.com').scim_active is True


def test_role_lifecycle_revisions_and_one_audit_event_per_change(governance):
    service = governance
    created = role(service, 'operator', ['workspace.read', 'connections.read', 'connections.manage'])
    assert created['revision'] == 1 and created['permissions'] == ['connections.manage', 'connections.read', 'workspace.read']
    with pytest.raises(GovernanceConflict) as error:
        role(service, 'operator')
    denied(error, 409, 'A role with this ID already exists.')
    update = RoleUpdate(name='Operator', description='Ops', permissions=['workspace.read'], revision=1)
    assert service.enterprise.update('operator', update, OWNER)['revision'] == 2
    with pytest.raises(GovernanceConflict) as error:
        service.enterprise.update('operator', update, OWNER)
    denied(error, 409, STALE)
    with pytest.raises(GovernanceNotFound):
        service.enterprise.update('missing', update, OWNER)
    with pytest.raises(GovernanceConflict) as error:
        service.enterprise.archive('operator', 1, OWNER)
    denied(error, 409, STALE)
    archived = service.enterprise.archive('operator', 2, OWNER)
    assert archived['archived'] and archived['revision'] == 3
    assert service.enterprise.archive('operator', 3, OWNER) == archived  # Idempotent, no second event.
    with pytest.raises(GovernanceConflict) as error:
        service.enterprise.update('operator', update.model_copy(update={'revision': 3}), OWNER)
    denied(error, 409, 'Archived roles cannot be edited.')
    with pytest.raises(GovernanceConflict):
        role(service, 'operator')  # Archived ids stay reserved.
    with pytest.raises(GovernanceInvalid):
        assign(service, 'bob@example.com', 'operator')
    with pytest.raises(GovernanceInvalid):
        service.enterprise.archive('admin', 0, OWNER)
    with pytest.raises(ValidationError):
        RoleCreate(id='member', name='Member', permissions=[])
    with pytest.raises(ValidationError):
        RoleCreate(id='reader', name='Reader', permissions=['invented.permission'])
    assert [row['action'] for row in events(service) if row['resource_type'] == 'role'] == [
        'role.created', 'role.updated', 'role.archived']
    detail = json.loads(events(service, 'role.updated')[0]['details'])
    assert detail == {'previous': ['connections.manage', 'connections.read', 'workspace.read'],
                      'permissions': ['workspace.read'], 'revision': 2}
    assert {row['actor'] for row in events(service) if row['resource_type'] == 'role'} == {'owner@example.com'}


def test_failed_mutation_leaves_no_event_and_no_change(governance, monkeypatch):
    service = governance
    role(service)

    def fail(*args, **kwargs):
        raise RuntimeError('synthetic failure after the write')

    original = enterprise_roles.record_event_in
    monkeypatch.setattr(enterprise_roles, 'record_event_in', lambda *a, **k: (original(*a, **k), fail()))
    with pytest.raises(RuntimeError):
        assign(service, 'bob@example.com', 'reader')
    assert not service.store.rows('SELECT * FROM enterprise_role_assignments')
    assert not events(service, 'role_assignment.updated')


def test_admin_is_granted_only_on_the_users_page_and_never_to_groups(governance):
    service = governance
    role(service)
    with pytest.raises(GovernanceInvalid) as error:
        assign(service, 'bob@example.com', 'admin')
    denied(error, 422, 'Grant administrator access on the Users page.')
    team = directory_group(service, 'Ops', [provision(service, 'bob@example.com')])
    for role_id, detail in (('admin', 'Administrator access cannot be granted to a group.'),
                            ('member', 'Choose a custom role or no additional role.')):
        with pytest.raises(GovernanceInvalid) as error:
            service.enterprise.set_group_role(team, GroupRoleChange(role_id=role_id), OWNER)
        denied(error, 422, detail)
    # A custom role would not narrow a built-in administrator; refuse instead of silently demoting.
    with pytest.raises(GovernanceConflict) as error:
        assign(service, 'owner@example.com', 'reader')
    assert 'administrator' in error.value.detail
    with pytest.raises(GovernanceInvalid) as error:
        assign(service, 'outside@elsewhere.test', 'reader')
    with pytest.raises(GovernanceNotFound):
        service.enterprise.set_group_role('f' * 32, GroupRoleChange(role_id='reader'), OWNER)


def delegated(service, email, permissions, *, via_group=()):
    """email holds `permissions` directly, plus via_group through a directory group grant."""
    identity = email.split('@')[0] + '-direct'
    role(service, identity, sorted(permissions))
    assign(service, email, identity)
    if via_group:
        role(service, identity + '-group', sorted(via_group))
        team = directory_group(service, identity + ' group', [provision(service, email)])
        service.enterprise.set_group_role(team, GroupRoleChange(role_id=identity + '-group'), OWNER)
        return team
    return None


def test_group_derived_authority_cannot_become_a_direct_assignment(governance):
    """Regression: delegates copied group-only roles.manage into a direct row that outlived the group."""
    service = governance
    team = delegated(service, 'dee@example.com', READER,
                     via_group={'roles.manage', 'users.read', 'audit.read', 'workspace.read'})
    role(service, 'access-admins', ['audit.read', 'roles.manage', 'users.read', 'workspace.read'])
    dee = person('dee@example.com')
    assert 'roles.manage' in access(service, 'dee@example.com').permissions
    with pytest.raises(GovernanceForbidden) as error:
        assign(service, 'dee@example.com', 'access-admins', revision=1, actor=dee)
    denied(error, 403, SELF)
    # Granting to a colleague is bounded by what dee holds directly, not through the group.
    assign(service, 'pal@example.com', 'dee-direct')
    with pytest.raises(GovernanceForbidden) as error:
        assign(service, 'pal@example.com', 'access-admins', revision=1, actor=dee)
    denied(error, 403, AMPLIFY)
    # Member defaults exceed dee's direct permissions, so dee cannot restore them either.
    with pytest.raises(GovernanceForbidden) as error:
        assign(service, 'pal@example.com', 'member', revision=1, actor=dee)
    denied(error, 403, AMPLIFY)
    with pytest.raises(GovernanceForbidden) as error:
        role(service, 'auditor', ['audit.read'], actor=dee)
    denied(error, 403, AMPLIFY)
    # The delegate's own group grant cannot be changed by that delegate either.
    with pytest.raises(GovernanceForbidden) as error:
        service.enterprise.set_group_role(team, GroupRoleChange(role_id=None, revision=1), dee)
    denied(error, 403, OWN_GROUP)
    listing = service.enterprise.listing(dee)
    assert listing['grantable'] == READER and listing['builtin_admin'] is False
    assert service.enterprise.listing(OWNER)['grantable'] is None
    # Leaving the group removes the authority; nothing direct was copied.
    service.scim.write(service.header, {}, 'Group', 'PUT', {'displayName': 'dee-direct group', 'members': []}, team)
    assert access(service, 'dee@example.com').permissions == set(READER)
    with pytest.raises(GovernanceForbidden) as error:
        service.enterprise.listing(dee)
    denied(error, 403, FORBIDDEN)


def test_delegates_cannot_redefine_roles_that_reach_them(governance):
    """Regression: a delegate widened the role granted to their own directory group, which kept a
    group-derived copy of their direct authority after the direct role was revoked."""
    service = governance
    engineering = directory_group(service, 'Engineering', [provision(service, 'dee@example.com'),
                                                           provision(service, 'other@example.com')])
    role(service, 'eng-base', ['workspace.read'])
    service.enterprise.set_group_role(engineering, GroupRoleChange(role_id='eng-base'), OWNER)
    authority = ['audit.read', 'roles.manage', 'security.manage', 'sessions.read', 'workspace.read']
    role(service, 'access-admin', authority)
    assign(service, 'dee@example.com', 'access-admin')
    dee = person('dee@example.com')
    with pytest.raises(GovernanceForbidden) as error:
        service.enterprise.set_group_role(engineering, GroupRoleChange(role_id='access-admin', revision=1), dee)
    denied(error, 403, OWN_GROUP)
    # Every direction is refused, as for the group grant itself: widening, narrowing and archiving.
    attempts = [
        (lambda: service.enterprise.update('eng-base', RoleUpdate(name='Eng base', permissions=authority, revision=1),
                                           dee), OWN_GROUP),
        (lambda: service.enterprise.update('eng-base', RoleUpdate(name='Eng base', permissions=[], revision=1), dee),
         OWN_GROUP),
        (lambda: service.enterprise.archive('eng-base', 1, dee), OWN_GROUP),
        # The delegate's own direct role is their own access too.
        (lambda: service.enterprise.update('access-admin', RoleUpdate(name='Access admin', permissions=authority,
                                                                      description='Mine', revision=1), dee), SELF),
        (lambda: service.enterprise.archive('access-admin', 1, dee), SELF),
    ]
    for attempt, detail in attempts:
        with pytest.raises(GovernanceForbidden) as error:
            attempt()
        denied(error, 403, detail)
    assert [(row['id'], row['permissions'], row['revision'], row['archived']) for row in service.store.rows(
        "SELECT id,permissions,revision,archived FROM enterprise_roles WHERE id IN ('eng-base','access-admin') ORDER BY id")] == [
        ('access-admin', json.dumps(authority), 1, 0), ('eng-base', '["workspace.read"]', 1, 0)]
    assert not events(service, 'role.updated') and not events(service, 'role.archived')
    # Roles that reach neither the delegate nor their groups stay editable within the direct set.
    role(service, 'helper', ['workspace.read'], actor=dee)
    assert service.enterprise.update('helper', RoleUpdate(name='Helper', permissions=['sessions.read', 'workspace.read'],
                                                          revision=1), dee)['revision'] == 2
    # Revoking the direct role leaves neither dee nor the group with copied authority.
    assign(service, 'dee@example.com', 'member', revision=1)
    for email in ('dee@example.com', 'other@example.com'):
        held = access(service, email).permissions
        assert held == MEMBER_PERMISSIONS | {'workspace.read'} and not held & {'roles.manage', 'security.manage'}
    with pytest.raises(GovernanceForbidden) as error:
        service.enterprise.listing(dee)
    denied(error, 403, FORBIDDEN)


def test_returning_to_default_never_restores_an_earlier_authority_entry(governance):
    """Regression: a reset to 'member', SCIM reactivation or reprovisioning, rejoining a granted group and
    re-widening a granted role each restored the exact pre-revocation entry, reviving saved authority."""
    service = governance
    patch_op = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'

    def entries(email, *changes):
        seen = [access(service, email).authority_entry()]
        for change in changes:
            change()
            seen.append(access(service, email).authority_entry())
        keys = [json.dumps(entry, sort_keys=True) for entry in seen]
        assert len(set(keys)) == len(keys), seen
        return seen

    role(service)
    maya = entries('maya@example.com', lambda: assign(service, 'maya@example.com', 'reader'),
                   lambda: assign(service, 'maya@example.com', 'member', revision=1),
                   lambda: assign(service, 'maya@example.com', 'reader', revision=2),
                   lambda: assign(service, 'maya@example.com', 'member', revision=3))
    assert maya[0] is None and maya[-1]['assignment_revision'] == 4

    pat = provision(service, 'pat@example.com')

    def active(value):
        return lambda: service.scim.write(service.header, {}, 'User', 'PATCH', {'schemas': [patch_op], 'Operations': [
            {'op': 'replace', 'path': 'active', 'value': value}]}, pat)

    pats = entries('pat@example.com', active(False), active(True), active(False), active(True))
    assert pats[0] is None and pats[2]['directory'] == [pat, 1] and pats[4]['directory'] == [pat, 2]
    assert access(service, 'pat@example.com').default  # Same access as before, but no earlier entry.

    sam = provision(service, 'sam@example.com')
    replacements = []
    sams = entries('sam@example.com', lambda: service.scim.delete(service.header, 'User', sam),
                   lambda: replacements.append(provision(service, 'sam@example.com')),
                   lambda: service.scim.delete(service.header, 'User', replacements[0]),
                   lambda: replacements.append(provision(service, 'sam@example.com')))
    assert sams[0] is None and sams[2]['directory'] == [replacements[0], 1]
    assert sams[4]['directory'] == [replacements[1], 1] and sams[4]['permissions'] == sorted(MEMBER_PERMISSIONS)

    role(service, 'operator', ['connections.manage', 'workspace.read'])
    lee = provision(service, 'lee@example.com')
    ops = directory_group(service, 'Ops', [lee])
    service.enterprise.set_group_role(ops, GroupRoleChange(role_id='operator'), OWNER)

    def operator(permissions, revision):
        return lambda: service.enterprise.update('operator', RoleUpdate(name='Operator', permissions=permissions,
                                                                        revision=revision), OWNER)

    lees = entries('lee@example.com',
                   lambda: service.scim.write(service.header, {}, 'Group', 'PATCH', {'schemas': [patch_op], 'Operations': [
                       {'op': 'remove', 'path': f'members[value eq "{lee}"]'}]}, ops),
                   lambda: service.scim.write(service.header, {}, 'Group', 'PUT', {'displayName': 'Ops',
                                                                                  'members': [{'value': lee}]}, ops),
                   lambda: service.scim.write(service.header, {}, 'Group', 'PUT', {'displayName': 'Ops', 'members': []}, ops),
                   lambda: service.scim.write(service.header, {}, 'Group', 'PATCH', {'schemas': [patch_op], 'Operations': [
                       {'op': 'add', 'path': 'members', 'value': [{'value': lee}]}]}, ops),
                   operator(['workspace.read'], 1), operator(['connections.manage', 'workspace.read'], 2))
    assert lees[0]['grant_roles'] == [['operator', 1]] and 'directory' not in lees[0]
    assert lees[2]['directory'] == [lee, 1] and lees[4]['directory'] == [lee, 2]
    assert lees[-1]['grant_roles'] == [['operator', 3]] and lees[-1]['permissions'] == lees[0]['permissions']

    # Ending the only grant, by clearing it or deleting its group, also never restores the earlier entry.
    for end in ('clear', 'delete'):
        ray = provision(service, f'ray-{end}@example.com')
        team = directory_group(service, f'Team {end}', [ray])

        def grant(role_id, revision, team=team):
            return lambda: service.enterprise.set_group_role(team, GroupRoleChange(role_id=role_id, revision=revision),
                                                             OWNER)

        rays = entries(f'ray-{end}@example.com', grant('operator', 0),
                       grant(None, 1) if end == 'clear' else lambda team=team: service.scim.delete(
                           service.header, 'Group', team))
        assert rays[0] is None and rays[2]['directory'] == [ray, 1]

    # People governance never touched keep no entry: provisioning, grantless groups, joining and leaving them.
    kim = provision(service, 'kim@example.com')
    readers = directory_group(service, 'Readers', [kim])
    service.scim.write(service.header, {}, 'Group', 'PUT', {'displayName': 'Readers', 'members': []}, readers)
    assert access(service, 'kim@example.com').authority_entry() is None


def test_archiving_or_narrowing_a_granted_role_never_restores_the_pre_grant_entry(governance):
    """Regression: a group grant whose role was archived, or swapped for a member subset, left a default
    state with no entry, which revived authority versions issued before the grant."""
    service = governance
    role(service, 'auditor', ['audit.read'])
    role(service, 'subset', ['workspace.read'])
    for end in ('subset', 'archive'):
        email = f'pat-{end}@example.com'
        team = directory_group(service, f'Audit {end}', [provision(service, email)])
        seen = [access(service, email).authority_entry()]
        service.enterprise.set_group_role(team, GroupRoleChange(role_id='auditor'), OWNER)
        seen.append(access(service, email).authority_entry())
        if end == 'archive':
            service.enterprise.archive('auditor', 1, OWNER)
        else:
            service.enterprise.set_group_role(team, GroupRoleChange(role_id='subset', revision=1), OWNER)
        state = access(service, email)
        seen.append(state.authority_entry())
        assert state.default and seen[0] is None
        assert len({json.dumps(entry, sort_keys=True) for entry in seen}) == 3, seen


def test_role_renames_keep_holders_authority_and_admins_ignore_group_grants(governance):
    """Regression: every role edit advanced the authority revision, so fixing a description revoked every
    holder's saved grants; group grants also changed built-in administrators' versions."""
    service = governance
    role(service, 'operator', ['connections.manage', 'workspace.read'])
    assign(service, 'bob@example.com', 'operator')
    team = directory_group(service, 'Ops', [provision(service, 'lee@example.com'),
                                            provision(service, 'owner@example.com')])
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='operator'), OWNER)
    holders = ('bob@example.com', 'lee@example.com')

    def entries():
        return {email: access(service, email).authority_entry() for email in holders}

    before = entries()
    renamed = service.enterprise.update('operator', RoleUpdate(
        name='Operations', description='Typo fixed', permissions=['workspace.read', 'connections.manage'],
        revision=1), OWNER)
    assert renamed['revision'] == 2 and entries() == before  # Still revision-checked, but nothing revoked.
    with pytest.raises(GovernanceConflict):
        service.enterprise.update('operator', RoleUpdate(name='Stale', permissions=[], revision=1), OWNER)
    service.enterprise.update('operator', RoleUpdate(name='Operations', permissions=['workspace.read'],
                                                     revision=2), OWNER)
    narrowed = entries()
    assert all(narrowed[email] != before[email] for email in holders)
    assert narrowed['bob@example.com']['role_revision'] == 3
    assert narrowed['lee@example.com']['grant_roles'] == [['operator', 3]]
    service.enterprise.archive('operator', 3, OWNER)
    assert all(entry not in (before[email], narrowed[email]) for email, entry in entries().items())
    # A built-in administrator always holds every permission; group grants never touch their version.
    admin = access(service, 'owner@example.com')
    assert admin.permissions == ALL and admin.groups == () and admin.authority_entry() is None


def test_delegates_cannot_strip_or_archive_access_they_do_not_hold(governance):
    """Regression: the delegation bound covered additions only, so delegates removed others' access."""
    service = governance
    delegated(service, 'del@example.com', {'roles.manage', 'workspace.read'})
    delegate = person('del@example.com')
    role(service, 'secops', ['audit.read', 'scim.manage', 'security.manage', 'workspace.read'])
    assign(service, 'sec@example.com', 'secops')
    team = directory_group(service, 'Security', [provision(service, 'sec2@example.com')])
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='secops'), OWNER)
    role(service, 'empty', [])
    attempts = [
        (lambda: service.enterprise.archive('secops', 1, delegate), HELD_ROLE),
        (lambda: service.enterprise.update('secops', RoleUpdate(name='Secops', permissions=['workspace.read'],
                                                                revision=1), delegate), HELD_ROLE),
        (lambda: assign(service, 'sec@example.com', 'empty', revision=1, actor=delegate), HELD_PERSON),
        (lambda: service.enterprise.set_group_role(team, GroupRoleChange(role_id=None, revision=1), delegate), HELD_GRANT),
        # Member defaults exceed this delegate's direct permissions too.
        (lambda: assign(service, 'plain@example.com', 'empty', actor=delegate), HELD_PERSON),
    ]
    for attempt, detail in attempts:
        with pytest.raises(GovernanceForbidden) as error:
            attempt()
        denied(error, 403, detail)
    assert access(service, 'sec@example.com').permissions == {'audit.read', 'scim.manage', 'security.manage', 'workspace.read'}
    assert not events(service, 'role.archived')
    # Within its direct set a delegate may act on others.
    broad = person('broad@example.com')
    delegated(service, 'broad@example.com', MEMBER_PERMISSIONS | {'roles.manage'})
    role(service, 'helper', ['sessions.read', 'workspace.read'], actor=broad)
    assert assign(service, 'plain@example.com', 'helper', actor=broad)['revision'] == 1
    assert assign(service, 'plain@example.com', 'member', revision=1, actor=broad)['role_id'] == 'member'
    with pytest.raises(GovernanceForbidden) as error:
        assign(service, 'owner@example.com', 'member', actor=broad)
    denied(error, 403, ADMIN_ONLY)
    # The built-in administrator is unrestricted.
    assert service.enterprise.archive('secops', 1, OWNER)['archived']


def test_assignment_revisions_cover_both_pages(governance):
    """Regression: the roles tab and users page could not see each other's revisions."""
    from app.user_roles import RoleChange
    service = governance
    role(service)
    role(service, 'contractor', ['workspace.read'])
    first = assign(service, 'ava@example.com', 'reader', role_revision=0)
    assert first['revision'] == 1 and first['role_revision'] == 0
    with pytest.raises(GovernanceConflict) as error:
        assign(service, 'ava@example.com', 'contractor', revision=0)
    denied(error, 409, STALE)
    # The users page replaces the custom role; a roles tab that still shows it is stale.
    service.roles.change(RoleChange(email='ava@example.com', role='member', revision=0,
                                    replace_custom_role=True, access_revision=1), OWNER)
    with pytest.raises(GovernanceConflict) as error:
        assign(service, 'ava@example.com', 'contractor', revision=1)
    denied(error, 409, STALE)
    # The resulting member row reads as no assignment (revision 0) and is accepted as such.
    assert assign(service, 'ava@example.com', 'contractor', revision=0)['revision'] == 3
    # Built-in role changes bump the user_roles revision the roles tab sent.
    service.roles.change(RoleChange(email='bob@example.com', role='admin', revision=0), OWNER)
    service.roles.change(RoleChange(email='bob@example.com', role='member', revision=1), OWNER)
    with pytest.raises(GovernanceConflict) as error:
        assign(service, 'bob@example.com', 'reader', role_revision=0)
    denied(error, 409, STALE)
    assert assign(service, 'bob@example.com', 'reader', role_revision=2)['role_revision'] == 2
    assert [json.loads(row['details'])['replacement'] for row in events(service, 'role_assignment.updated')] == [
        'reader', 'member', 'contractor', 'reader']


def test_actor_snapshots_are_rechecked_in_the_writer(governance):
    service = governance
    delegated(service, 'mgr@example.com', MEMBER_PERMISSIONS | {'roles.manage'})
    # A stale principal that no longer holds roles.manage cannot write, whatever the database says.
    stale = person('mgr@example.com', permissions=MEMBER_PERMISSIONS)
    with pytest.raises(GovernanceForbidden):
        role(service, 'reader', actor=stale)
    # Revocation after authentication wins over the principal's snapshot.
    snapshot = person('mgr@example.com', permissions=MEMBER_PERMISSIONS | {'roles.manage'})
    assign(service, 'mgr@example.com', 'member', revision=1)
    with pytest.raises(GovernanceForbidden):
        role(service, 'reader', actor=snapshot)
    # A principal claiming administrator authority is still checked against the canonical role.
    with pytest.raises(GovernanceForbidden):
        role(service, 'reader', actor=person('mgr@example.com', 'admin', ALL))
    # Deactivated, foreign-domain, Slack and unauthenticated actors fail closed.
    provision(service, 'mgr@example.com', active=False)
    for actor, error_type in ((person('mgr@example.com', permissions=ALL), GovernanceForbidden),
                              (person('x@elsewhere.test', 'admin'), GovernanceForbidden),
                              (GovernanceActor(id='slack:T:U', email='owner@example.com', builtin_role='admin'),
                               GovernanceForbidden),
                              (None, GovernanceError)):
        with pytest.raises(error_type):
            role(service, 'reader', actor=actor)
    with pytest.raises(GovernanceForbidden) as error:
        role(service, 'reader', actor=person('mgr@example.com'))
    denied(error, 403, DEACTIVATED)
    # ProductPrincipal-shaped objects are accepted.
    principal = SimpleNamespace(id='google:owner', kind='google', method='google', email='owner@example.com',
                                role='admin', permissions=ALL)
    assert role(service, 'reader', actor=principal)['updated_by'] == 'owner@example.com'
    # Actors without a role claim defer to the canonical role; mappings and other malformed actors fail closed.
    unclaimed = GovernanceActor(id='google:owner', email='Owner@Example.com', builtin_role=None, kind='individual')
    assert role(service, 'second', actor=unclaimed)['revision'] == 1
    for actor in ({'id': 'google:x', 'email': None}, {'id': None}, {'method': 'invented', 'role': 'admin'},
                  {'method': 'google', 'role': 'admin', 'identity': {'email': 'owner@example.com', 'sub': 'owner'}},
                  SimpleNamespace(id=None, role='admin'), object()):
        with pytest.raises(GovernanceForbidden):
            role(service, 'fourth', actor=actor)


def test_shared_actors_follow_the_current_sign_in_configuration(governance):
    service = governance
    settings = service.settings
    settings.password_login_enabled, settings.workspace_password = True, 'test-only-shared-admin-password'
    shared = GovernanceActor(id='shared:password:admin', builtin_role='admin')
    assert role(service, 'reader', actor=shared)['updated_by'] == 'Shared password admin'
    for actor in (GovernanceActor(id='shared:password:member', builtin_role='admin'),
                  GovernanceActor(id='shared:invented:admin', builtin_role='admin')):
        with pytest.raises(GovernanceForbidden):
            role(service, 'other', actor=actor)
    settings.password_login_enabled = False
    with pytest.raises(GovernanceForbidden):
        role(service, 'other', actor=shared)


def statements(monkeypatch):
    import sqlite3

    from app.database import PostgresConnection, SQLiteConnection
    executed = []
    for kind, execute in ((SQLiteConnection, sqlite3.Connection.execute), (PostgresConnection, PostgresConnection.execute)):
        monkeypatch.setattr(kind, 'execute', lambda conn, *args, execute=execute: executed.append(args[0]) or execute(conn, *args))
    return executed


def test_listing_shape_and_constant_statement_count(governance, monkeypatch):
    service = governance
    role(service)
    role(service, 'zeta', ['workspace.read'])
    assign(service, 'bob@example.com', 'reader')
    assign(service, 'carl@example.com', 'reader')
    assign(service, 'carl@example.com', 'member', revision=1)
    people = [provision(service, f'p{index}@example.com') for index in range(3)]
    team = directory_group(service, 'Engineering', people)
    directory_group(service, 'alumni')
    service.scim.write(service.header, {}, 'User', 'PATCH', {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                       'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]}, people[0])
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='zeta'), OWNER)
    listing = service.enterprise.listing(OWNER)
    assert [row['id'] for row in listing['roles']] == ['reader', 'zeta']
    assert [(row['email'], row['role_id'], row['role_name']) for row in listing['assignments']] == [
        ('bob@example.com', 'reader', 'Reader')]
    assert listing['group_roles'][0] | {'updated_at': None} == {
        'group_id': team, 'group_name': 'Engineering', 'role_id': 'zeta', 'role_name': 'Zeta', 'revision': 1,
        'updated_at': None, 'updated_by': 'owner@example.com'}
    assert [(row['display_name'], row['member_count']) for row in listing['groups']] == [('alumni', 0), ('Engineering', 2)]
    assert listing['grantable'] is None and listing['builtin_admin'] is True
    executed = statements(monkeypatch)
    service.enterprise.listing(OWNER)
    baseline = len(executed)
    for index in range(5):
        directory_group(service, f'extra {index}', people[1:])
        assign(service, f'more{index}@example.com', 'reader')
    executed.clear()
    service.enterprise.listing(OWNER)
    assert len(executed) == baseline


def test_services_are_synchronous_libraries_without_routes():
    """Regression: governance handlers blocked the event loop; the native HTTP layer owns threading."""
    from app import user_roles
    for service in (enterprise_roles.EnterpriseRoles, user_roles.UserRoles):
        for name, method in inspect.getmembers(service, inspect.isfunction):
            assert not inspect.iscoroutinefunction(method), name
        assert not hasattr(service, 'routes')


def test_actor_labels_match_across_governance_writers():
    """Security profiles and spend limits label changes with the same text as roles and SCIM tokens."""
    from app.enterprise_roles import actor_label
    assert actor_label(person('Owner@Example.com', 'admin')) == 'owner@example.com'
    assert actor_label(GovernanceActor(id='shared:local:admin')) == 'Local preview admin'
    assert actor_label(GovernanceActor(id='shared:password:member')) == 'Shared password member'
    assert actor_label(GovernanceActor(id='google:1', email='A@Example.com', kind='individual')) == 'a@example.com'
    google = SimpleNamespace(id='google:1', kind='google', method='google', email='Owner@Example.com', individual=True)
    assert actor_label(google) == 'owner@example.com'
    # A Slack-claimed profile email never labels a governance change.
    slack = SimpleNamespace(id='slack:T1:U1', kind='slack', method='slack', email='owner@example.com', individual=False)
    assert actor_label(slack) == 'slack:T1:U1'
    assert actor_label(GovernanceActor(id='shared:invented:admin')) == 'shared:invented:admin'
    for actor in (None, object(), 'owner@example.com', GovernanceActor(id=''), GovernanceActor(id='x' * 513),
                  GovernanceActor(id='google:\x00'), {'method': 'invented'},
                  {'method': 'password', 'role': 'member'}):
        with pytest.raises(TypeError):
            actor_label(actor)


def test_every_governance_service_keeps_database_work_off_the_event_loop():
    """Only Scim.body is a coroutine, and it reaches the database only through app.db.database."""
    from app import governance_audit, scim, security_profiles, spend_limits
    for service in (governance_audit.GovernanceAudit, security_profiles.SecurityProfiles, spend_limits.SpendLimits,
                    scim.Scim):
        coroutines = {name for name, method in inspect.getmembers(service, inspect.isfunction)
                      if inspect.iscoroutinefunction(method)}
        assert coroutines == ({'body'} if service is scim.Scim else set()), service
    tree = ast.parse(textwrap.dedent(inspect.getsource(scim.Scim.body)))
    awaited = [node.value for node in ast.walk(tree) if isinstance(node, ast.Await)]
    assert [call.func.id for call in awaited if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)] == [
        'database']
    for module in (security_profiles, spend_limits):
        assert module.actor_label is enterprise_roles.actor_label
