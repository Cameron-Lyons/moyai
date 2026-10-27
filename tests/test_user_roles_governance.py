"""Built-in roles alongside custom roles and SCIM state, on SQLite or --postgres-backend."""
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from app.config import Settings
from app.db import Store
from app.enterprise_roles import (
    ADMIN_ONLY,
    AMPLIFY,
    FORBIDDEN,
    HELD_PERSON,
    SELF,
    STALE,
    GovernanceActor,
    GovernanceConflict,
    GovernanceForbidden,
    GroupRoleChange,
    RoleAssignment,
    RoleCreate,
)
from app.permissions import BUILTIN_PERMISSIONS, MEMBER_PERMISSIONS
from app.scim import API, Scim
from app.user_roles import CUSTOM_ROLE, LAST_ADMIN, RoleChange, UserRoles
from fastapi import HTTPException

ALL = BUILTIN_PERMISSIONS['admin']


def person(email, role='member', permissions=None):
    return GovernanceActor(id='google:' + email.split('@')[0], email=email, builtin_role=role,
                           permissions=permissions, kind='individual')


OWNER = person('owner@example.com', 'admin')


@pytest.fixture
def directory(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com,second@example.com')
    store = Store(tmp_path)
    try:
        roles = UserRoles(store, settings)
        scim = Scim(store, roles, base_url='http://localhost:8787/scim/v2')
        _, token = scim.create_token('Directory', OWNER)
        yield SimpleNamespace(store=store, settings=settings, roles=roles, enterprise=roles.enterprise, scim=scim,
                              header='Bearer ' + token)
    finally:
        store.close()


def signed_in(service, email, kind='google'):
    stamp = '2026-10-16T00:00:00+00:00'
    service.store.execute('INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                          (f'{kind}:{email}', kind, email, email.split('@')[0].title(), stamp, stamp))


def provision(service, email, *, active=True):
    return service.scim.write(service.header, {}, 'User', 'POST', {'userName': email, 'active': active})['id']


def deactivate(service, identity):
    return service.scim.write(service.header, {}, 'User', 'PATCH', {'schemas': [API + 'PatchOp'], 'Operations': [
        {'op': 'replace', 'path': 'active', 'value': False}]}, identity)


def custom(service, email, identity='reader', permissions=('sessions.read', 'workspace.read')):
    if not service.store.rows('SELECT 1 FROM enterprise_roles WHERE id=?', (identity,)):
        service.enterprise.create(RoleCreate(id=identity, name=identity.title(), permissions=list(permissions)), OWNER)
    row = service.store.rows('SELECT revision FROM enterprise_role_assignments WHERE email=?', (email,))
    return service.enterprise.assign(RoleAssignment(email=email, role_id=identity,
                                                    revision=row[0]['revision'] if row else 0), OWNER)


def change(service, email, role, revision=0, actor=OWNER, **extra):
    return service.roles.change(RoleChange(email=email, role=role, revision=revision, **extra), actor)


def statements(monkeypatch):
    import sqlite3

    from app.database import PostgresConnection, SQLiteConnection
    executed = []
    for kind, execute in ((SQLiteConnection, sqlite3.Connection.execute), (PostgresConnection, PostgresConnection.execute)):
        monkeypatch.setattr(kind, 'execute', lambda conn, *args, execute=execute: executed.append(args[0]) or execute(conn, *args))
    return executed


def denied(error, status, detail):
    assert (error.value.status_code, error.value.detail) == (status, detail)


def test_role_query_and_product_identity_construction_are_unchanged(directory, monkeypatch):
    # native product_identity adapts exactly this statement and builds UserRoles without a store.
    seen = []

    class Recorder:
        def execute(self, statement, parameters):
            seen.append(statement)
            return SimpleNamespace(fetchone=lambda: None)

    roles = UserRoles(SimpleNamespace(schema_updates=False), directory.settings)
    assert roles.role_in(Recorder(), 'owner@example.com') == 'admin' and roles.role_in(Recorder(), 'x@example.com') == 'member'
    assert seen == ['SELECT role FROM user_roles WHERE email=?'] * 2
    assert roles.eligible('a@example.com') and not roles.eligible('a@elsewhere.test')
    assert roles.default_role('second@example.com') == 'admin'


def test_directory_reports_custom_roles_activity_and_effective_permissions(directory, monkeypatch):
    service = directory
    for email in ('maya@example.com', 'mo@example.com', 'old@example.com', 'grace@example.com', 'dan@example.com'):
        signed_in(service, email)
    custom(service, 'maya@example.com')
    custom(service, 'old@example.com', 'retired', ['spend.read', 'workspace.read'])
    service.enterprise.archive('retired', 1, OWNER)
    service.enterprise.create(RoleCreate(id='connector', name='Connector', permissions=['connections.manage']), OWNER)
    grace, dan = provision(service, 'grace@example.com'), provision(service, 'dan@example.com')
    team = service.scim.write(service.header, {}, 'Group', 'POST', {'displayName': 'Connectors',
                              'members': [{'value': grace}, {'value': dan}]})['id']
    service.enterprise.set_group_role(team, GroupRoleChange(role_id='connector'), OWNER)
    deactivate(service, dan)
    deactivate(service, provision(service, 'second@example.com'))
    custom(service, 'mo@example.com')
    service.enterprise.assign(RoleAssignment(email='mo@example.com', role_id='member', revision=1), OWNER)
    rows = {row['email']: row for row in service.roles.directory()['users']}
    with service.store.connect() as conn:
        for email, row in rows.items():
            state = service.roles.access_in(conn, email)
            assert set(row['permissions']) == state.permissions, email
            assert (row['role'], row['active'], (row['access_role'] or {}).get('id')) == (
                service.roles.role_in(conn, email), state.scim_active is not False, state.role_id), email
    assert rows['maya@example.com']['access_role'] == {'id': 'reader', 'name': 'Reader', 'revision': 1}
    assert rows['maya@example.com']['permissions'] == ['sessions.read', 'workspace.read']
    assert set(rows['grace@example.com']['permissions']) == MEMBER_PERMISSIONS | {'connections.manage'}
    assert rows['grace@example.com']['access_role'] is None and rows['grace@example.com']['active'] is True
    assert rows['old@example.com']['access_role']['id'] == 'retired' and rows['old@example.com']['permissions'] == []
    assert rows['dan@example.com']['active'] is False and rows['dan@example.com']['permissions'] == []
    assert rows['second@example.com']['role'] == 'admin' and rows['second@example.com']['permissions'] == []
    # A built-in member row is no custom role, so the editor needs no confirmation to replace it.
    assert rows['mo@example.com']['access_role'] is None
    assert not {'access_role_id', 'access_role_name', 'access_revision'} & rows['mo@example.com'].keys()
    assert set(rows['owner@example.com']['permissions']) == ALL
    executed = statements(monkeypatch)
    service.roles.directory()
    baseline = len(executed)
    for index in range(20):
        signed_in(service, f'p{index}@example.com')
        custom(service, f'p{index}@example.com')
    executed.clear()
    service.roles.directory()
    assert len(executed) == baseline


def test_last_admin_guard_counts_only_active_administrators(directory):
    service = directory
    # second@ is a configured administrator, but SCIM deactivated them.
    owner = provision(service, 'owner@example.com')
    deactivate(service, provision(service, 'second@example.com'))
    with service.store.connect() as conn:
        assert service.roles.admins_in(conn) == {'owner@example.com'}
        assert service.roles.admin_holders_in(conn) == {'owner@example.com', 'second@example.com'}
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'owner@example.com', 'member')
    denied(error, 409, LAST_ADMIN)
    # A deactivated administrator can still be demoted, so reprovisioning cannot restore it.
    assert change(service, 'second@example.com', 'member')['revision'] == 1
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'second@example.com', 'admin', revision=1)
    assert error.value.detail == 'Activate this directory account before assigning administrator access.'
    # The SCIM writer protects the same last active administrator.
    from app.scim import ScimError
    with pytest.raises(ScimError) as scim_error:
        deactivate(service, owner)
    assert scim_error.value.status == 409


def test_replacing_a_custom_role_needs_confirmation_and_its_revision(directory):
    service = directory
    custom(service, 'ava@example.com')
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'ava@example.com', 'member')
    denied(error, 409, CUSTOM_ROLE)
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'ava@example.com', 'member', replace_custom_role=True)
    denied(error, 409, STALE)
    # A custom-to-custom change elsewhere bumps the assignment revision the users page showed.
    custom(service, 'ava@example.com', 'contractor', ['workspace.read'])
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'ava@example.com', 'member', replace_custom_role=True, access_revision=1)
    denied(error, 409, STALE)
    assert service.roles.permissions('ava@example.com') == {'workspace.read'}
    result = change(service, 'ava@example.com', 'member', replace_custom_role=True, access_revision=2)
    assert result == {'email': 'ava@example.com', 'role': 'member', 'revision': 0}
    assert service.roles.permissions('ava@example.com') == MEMBER_PERMISSIONS
    assert not service.store.rows('SELECT * FROM user_role_audit')  # The built-in role did not change.
    replaced = service.store.rows("SELECT details FROM governance_audit_events WHERE action='role_assignment.updated' "
                                  "ORDER BY created_at DESC LIMIT 1")[0]
    assert json.loads(replaced['details']) == {'previous': 'contractor', 'replacement': 'member', 'revision': 3}
    # Promotion while replacing records both the assignment and the built-in change.
    custom(service, 'ben@example.com')
    assert change(service, 'ben@example.com', 'admin', replace_custom_role=True, access_revision=1)['revision'] == 1
    assert service.roles.permissions('ben@example.com') == ALL
    assert [row['role'] for row in service.store.rows('SELECT role FROM user_role_audit')] == ['admin']
    with pytest.raises(GovernanceConflict) as error:
        change(service, 'ben@example.com', 'member', revision=0)
    denied(error, 409, STALE)


def test_delegated_built_in_role_editors_stay_within_their_bounds(directory):
    service = directory
    custom(service, 'maya@example.com')
    service.enterprise.create(RoleCreate(id='user-admin', name='User admin',
                              permissions=sorted(MEMBER_PERMISSIONS | {'users.read', 'users.manage'})), OWNER)
    service.enterprise.create(RoleCreate(id='access-admin', name='Access admin',
                              permissions=sorted(MEMBER_PERMISSIONS | {'users.read', 'users.manage', 'roles.manage'})), OWNER)
    service.enterprise.assign(RoleAssignment(email='ops@example.com', role_id='user-admin'), OWNER)
    service.enterprise.assign(RoleAssignment(email='lead@example.com', role_id='access-admin'), OWNER)
    ops, lead = person('ops@example.com'), person('lead@example.com')
    for target, role, revision in (('ops@example.com', 'admin', 0), ('owner@example.com', 'member', 0)):
        with pytest.raises(GovernanceForbidden) as error:
            change(service, target, role, revision, ops)
        denied(error, 403, ADMIN_ONLY)
    # Replacing a custom role needs roles.manage, not only users.manage.
    with pytest.raises(GovernanceForbidden) as error:
        change(service, 'maya@example.com', 'member', actor=ops, replace_custom_role=True, access_revision=1)
    denied(error, 403, FORBIDDEN)
    with pytest.raises(GovernanceForbidden) as error:
        change(service, 'ops@example.com', 'member', actor=ops, replace_custom_role=True, access_revision=1)
    denied(error, 403, SELF)
    assert change(service, 'new@example.com', 'member', actor=ops)['revision'] == 1
    assert change(service, 'maya@example.com', 'member', actor=lead, replace_custom_role=True, access_revision=1)
    assert service.roles.permissions('maya@example.com') == MEMBER_PERMISSIONS
    # A delegate cannot replace a custom role whose permissions exceed what it holds directly.
    custom(service, 'sec@example.com', 'secops', ['audit.read', 'security.manage'])
    with pytest.raises(GovernanceForbidden) as error:
        change(service, 'sec@example.com', 'member', actor=lead, replace_custom_role=True, access_revision=1)
    denied(error, 403, HELD_PERSON)
    # Member defaults must be held directly to grant them.
    service.enterprise.create(RoleCreate(id='narrow', name='Narrow', permissions=['users.manage', 'workspace.read']), OWNER)
    service.enterprise.assign(RoleAssignment(email='narrow@example.com', role_id='narrow'), OWNER)
    with pytest.raises(GovernanceForbidden) as error:
        change(service, 'fresh@example.com', 'member', actor=person('narrow@example.com'))
    denied(error, 403, AMPLIFY)


def test_unclaimed_actors_defer_to_the_canonical_role_and_errors_keep_their_status(directory):
    service = directory
    admin = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role=None, kind='individual')
    assert service.roles.change(RoleChange(email='new@example.com', role='member', revision=0), admin)['revision'] == 1
    member = GovernanceActor(id='google:new', email='new@example.com', builtin_role=None, kind='individual')
    with pytest.raises(HTTPException) as error:
        service.roles.change(RoleChange(email='other@example.com', role='member', revision=0), member)
    assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        service.roles.change(RoleChange(email='other@elsewhere.test', role='member', revision=0), admin)
    assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        service.roles.change(RoleChange(email='new@example.com', role='member', revision=0), None)
    assert error.value.status_code == 401
    with pytest.raises(GovernanceConflict) as error:
        service.roles.change(RoleChange(email='new@example.com', role='admin', revision=0), admin)
    denied(error, 409, STALE)
    assert service.roles.change(RoleChange(email='new@example.com', role='admin', revision=1), admin)['revision'] == 2
    audit = service.store.rows('SELECT email,previous_role,role,actor FROM user_role_audit ORDER BY id')
    assert audit[-1] == {'email': 'new@example.com', 'previous_role': 'member', 'role': 'admin', 'actor': 'owner@example.com'}


@pytest.mark.parametrize('order', [('owner@example.com', 'second@example.com'), ('second@example.com', 'owner@example.com')])
def test_concurrent_demotions_preserve_one_active_administrator(directory, order):
    service = directory
    barrier = Barrier(2)

    def demote(email):
        barrier.wait(timeout=5)
        try:
            # Each administrator steps down at once; the writer serializes the last-admin check.
            change(service, email, 'member', actor=person(email, 'admin'))
            return 200
        except HTTPException as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(demote, order))
    assert sorted(outcomes) == [200, 409]
    with service.store.connect() as conn:
        assert len(service.roles.admins_in(conn)) == 1


def test_concurrent_demotion_and_deactivation_preserve_one_active_administrator(directory):
    service = directory
    second = provision(service, 'second@example.com')
    provision(service, 'owner@example.com')
    barrier = Barrier(2)

    def demote():
        barrier.wait(timeout=5)
        try:
            change(service, 'owner@example.com', 'member')
            return 'demoted'
        except HTTPException as error:
            return error.status_code

    def deprovision():
        barrier.wait(timeout=5)
        try:
            deactivate(service, second)
            return 'deactivated'
        except HTTPException as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(demote), pool.submit(deprovision)]
        outcomes = sorted(str(future.result(timeout=30)) for future in futures)
    assert outcomes in (['409', 'deactivated'], ['409', 'demoted'])
    with service.store.connect() as conn:
        assert len(service.roles.admins_in(conn)) == 1


def test_security_person_resolves_directory_state_and_permissions(directory):
    from app.security import Security
    security = Security(directory.settings, directory.roles)
    assert security.person('owner@example.com') == {'role': 'admin', '_permissions': ALL}
    assert security.person('Dan@example.com') == {'role': 'member', '_permissions': MEMBER_PERMISSIONS}
    assert security.person('dan@other.test')['_permissions'] == frozenset()  # Ineligible domain.
    deactivate(directory, provision(directory, 'dan@example.com'))
    assert security.person('dan@example.com') is None


def test_oidc_accounts_are_individuals_for_directory_actors(directory):
    service = directory
    signed_in(service, 'ida@example.com', kind='oidc')
    custom(service, 'ida@example.com')
    row = next(row for row in service.roles.directory()['users'] if row['email'] == 'ida@example.com')
    assert row['has_signed_in'] and row['permissions'] == ['sessions.read', 'workspace.read']
    with service.store.connect() as conn:
        assert service.roles.permissions_for_actor_in(conn, 'oidc:ida@example.com') == {'sessions.read', 'workspace.read'}
    principal = SimpleNamespace(id='oidc:ida@example.com', kind='oidc', method='oidc', email='Ida@example.com',
                                role='member', permissions=frozenset({'sessions.read'}))
    actor = GovernanceActor.from_principal(principal)
    assert (actor.resolved_kind, actor.email) == ('individual', 'ida@example.com')
    # An earlier Google account that now signs in through the organization's provider.
    linked = GovernanceActor.from_principal(SimpleNamespace(**{**vars(principal), 'kind': 'google'}))
    assert linked.resolved_kind == 'individual'
