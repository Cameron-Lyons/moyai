"""Governance response models keep every key the canonical services return.

FastAPI filters output to the declared model, so a missing field would be
silently dropped. These run the real services on a canonical SQLite store.
"""

import json
from types import SimpleNamespace

import pytest
from app.config import Settings
from app.db import Store
from app.enterprise_roles import GovernanceActor, GroupRoleChange, RoleAssignment, RoleCreate, RoleUpdate
from app.governance_audit import AuditFilters, GovernanceAudit
from app.scim import CORE, Scim
from app.security_profiles import ProfileDefaults, SaveProfile, SecurityProfiles
from app.spend_limits import SpendLimitChanges, SpendLimits
from app.user_roles import UserRoles

from moyai.product_governance_views import (
    AuditPage,
    CreatedScimToken,
    GovernanceGroupRole,
    GovernanceRole,
    GovernanceRoleAssignment,
    RolesAdmin,
    ScimAdmin,
    ScimToken,
    SecurityProfileDefaults,
    SecurityProfilesAdmin,
    SecurityProfileView,
    SessionProfileCatalog,
    SpendLimitsAdmin,
)

OWNER = GovernanceActor(id='google:owner', email='owner@example.com', builtin_role='admin',
                        permissions=None, kind='individual')


@pytest.fixture
def services(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url='http://localhost:8787',
                        google_allowed_domains='example.com', google_admin_emails='owner@example.com')
    store = Store(tmp_path)
    try:
        roles = UserRoles(store, settings)
        yield SimpleNamespace(
            roles=roles.enterprise, scim=Scim(store, roles, base_url='http://localhost:8787/scim/v2'),
            profiles=SecurityProfiles(store, roles=roles.enterprise), spend=SpendLimits(store, roles=roles.enterprise),
            audit=GovernanceAudit(store, 'synthetic-governance-test-secret'),
        )
    finally:
        store.close()


def same(model, value):
    expected = json.loads(json.dumps(value))
    assert model.model_validate(value).model_dump(mode='json') == expected


def test_role_and_directory_responses_keep_every_service_key(services):
    created = services.roles.create(RoleCreate(id='reader', name='Reader', permissions=['sessions.read']), OWNER)
    same(GovernanceRole, created)
    same(GovernanceRole, services.roles.update('reader', RoleUpdate(
        name='Reader', description='Reads sessions', permissions=['sessions.read', 'workspace.read'], revision=1), OWNER))
    same(GovernanceRoleAssignment, services.roles.assign(RoleAssignment(
        email='person@example.com', role_id='reader', revision=0, role_revision=None), OWNER))
    _, token = services.scim.create_token('Directory', OWNER)
    header = 'Bearer ' + token
    person = services.scim.write(header, {}, 'User', 'POST',
                                 {'schemas': [CORE + 'User'], 'userName': 'person@example.com', 'active': True})['id']
    group = services.scim.write(header, {}, 'Group', 'POST',
                                {'displayName': 'Readers', 'members': [{'value': person}]})['id']
    same(GovernanceGroupRole, services.roles.set_group_role(group, GroupRoleChange(role_id='reader', revision=0), OWNER))
    listing = services.roles.listing(OWNER)
    assert listing['roles'] and listing['assignments'] and listing['group_roles'] and listing['groups']
    same(RolesAdmin, listing)
    directory = services.scim.directory(None, 50, OWNER)
    assert directory['users']['items'] and directory['groups'] and directory['tokens'] and directory['activity']
    same(ScimAdmin, directory)
    record, secret = services.scim.create_token('Second', OWNER)
    same(CreatedScimToken, {**record, 'token': secret})
    same(ScimToken, services.scim.revoke_token(record['id'], OWNER))
    archived = services.roles.archive('reader', 2, OWNER)
    assert archived['archived']
    same(GovernanceRole, archived)


def test_policy_spend_and_audit_responses_keep_every_service_key(services):
    policy = {'connected_apps': ['github'], 'tools': ['read_file'], 'git_access': 'read', 'network_domains': None}
    profile = services.profiles.save(SaveProfile(name='Restricted', enabled=True, policy=policy, revision=0), OWNER)
    same(SecurityProfileView, profile)
    same(SecurityProfileDefaults, services.profiles.save_defaults(ProfileDefaults(
        default_profile_id=profile['id'], mandatory_profile_id='', revision=0), OWNER))
    catalog = services.profiles.catalog()
    assert catalog['profiles'] and catalog['default_profile_id'] == profile['id']
    same(SessionProfileCatalog, catalog)
    admin = services.profiles.admin_listing()
    assert admin['catalog']['connected_apps'] and admin['catalog']['tools']
    same(SecurityProfilesAdmin, admin)
    spare = services.profiles.save(SaveProfile(name='Spare', enabled=True, policy=policy, revision=0), OWNER)
    same(SecurityProfileView, services.profiles.disable(spare['id'], spare['revision'], OWNER))
    services.spend.save(SpendLimitChanges(changes=[{'id': 'organization', 'limit_usd': 25.0, 'revision': 0}]), OWNER)
    limits = services.spend.listing()
    # The route adds used_usd to each row and usage to the listing.
    same(SpendLimitsAdmin, {**limits, 'limits': [{**row, 'used_usd': None} for row in limits['limits']],
                            'usage': None, 'can_manage': True})
    page = services.audit.listing(AuditFilters(), None, 50)
    assert {entry['source'] for entry in page['entries']} == {'governance'}
    same(AuditPage, page)
