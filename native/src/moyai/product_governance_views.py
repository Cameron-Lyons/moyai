"""Response models for the native governance routes.

The canonical governance services return plain dicts; these models are the
public contract (see .agents/skills/e2e-typesafety). Names are prefixed where a
canonical request model already uses the plain name.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, JsonValue


class GovernanceView(BaseModel):
    """Response payload: fields with defaults are still always present in output."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


class PermissionInfo(GovernanceView):
    id: str
    label: str
    description: str
    group: str


class BuiltinRolePermissions(GovernanceView):
    admin: list[str]
    member: list[str]


class PermissionCatalog(GovernanceView):
    permissions: list[str]
    catalog: list[PermissionInfo]
    builtin_roles: BuiltinRolePermissions


class GovernanceRole(GovernanceView):
    id: str
    name: str
    description: str
    permissions: list[str]
    revision: int
    archived: bool
    updated_at: str
    updated_by: str


class GovernanceRoleAssignment(GovernanceView):
    email: str
    role_id: str
    role_name: str
    revision: int
    # Revision of the person's built-in role when this row was read.
    role_revision: int
    updated_at: str | None
    updated_by: str


class GovernanceGroupRole(GovernanceView):
    group_id: str
    group_name: str
    role_id: str | None
    role_name: str | None
    revision: int
    updated_at: str | None
    updated_by: str


class DirectoryGroup(GovernanceView):
    id: str
    display_name: str
    member_count: int


class RolesAdmin(GovernanceView):
    roles: list[GovernanceRole]
    assignments: list[GovernanceRoleAssignment]
    group_roles: list[GovernanceGroupRole]
    groups: list[DirectoryGroup]
    # None for a built-in administrator (unrestricted).
    grantable: list[str] | None
    builtin_admin: bool


class AuditEntry(GovernanceView):
    id: str
    source: Literal["governance", "user_roles", "connections", "credentials"]
    action: str
    actor: str
    resource_type: str
    resource_id: str
    details: dict[str, JsonValue]
    created_at: str


class AuditFacets(GovernanceView):
    actions: list[str]
    resource_types: list[str]


class AuditPage(GovernanceView):
    entries: list[AuditEntry]
    next_cursor: str | None
    # Only the first page (no cursor) carries facets.
    facets: AuditFacets | None


class ScimUserSummary(GovernanceView):
    id: str
    user_name: str
    display_name: str
    active: bool
    external_id: str
    groups_count: int
    updated_at: str


class ScimUserPage(GovernanceView):
    items: list[ScimUserSummary]
    next_cursor: str | None


class ScimGroupSummary(GovernanceView):
    id: str
    display_name: str
    member_count: int
    role_id: str | None
    role_name: str | None


class ScimToken(GovernanceView):
    id: str
    label: str
    prefix: str
    created_at: str
    created_by: str
    last_used_at: str | None
    revoked_at: str | None


class CreatedScimToken(ScimToken):
    # The bearer token is returned once, here, and never again.
    token: str


class ScimAdmin(GovernanceView):
    base_url: str
    users: ScimUserPage
    # Only the first page (no cursor) carries the groups, tokens and activity.
    groups: list[ScimGroupSummary] | None
    tokens: list[ScimToken] | None
    activity: list[AuditEntry] | None
    # Only a built-in administrator can create provisioning tokens.
    can_create_tokens: bool


AppName = Literal["github", "linear", "slack", "notion"]


class PolicyView(GovernanceView):
    """null is unrestricted, [] allows nothing, and a list allows only its entries."""

    connected_apps: list[AppName] | None
    tools: list[str] | None
    git_access: Literal["write", "read", "none"]
    network_domains: list[str] | None
    # Permanent GitHub repository IDs.
    repositories: list[int] | None
    # Model choice IDs, matched exactly.
    models: list[str] | None


class SecurityProfileView(GovernanceView):
    id: str
    name: str
    enabled: bool
    revision: int
    policy: PolicyView
    updated_at: str
    updated_by: str


class SecurityProfileDefaults(GovernanceView):
    # "" selects no profile.
    default_profile_id: str
    mandatory_profile_id: str
    revision: int
    updated_at: str | None
    updated_by: str


class PolicyCatalogApp(GovernanceView):
    id: AppName
    label: str


class PolicyCatalogTool(GovernanceView):
    id: str
    label: str
    group: str


class PolicyCatalogRepository(GovernanceView):
    id: int
    # The repository's full name when it was last seen.
    label: str


class PolicyCatalogModel(GovernanceView):
    id: str
    label: str


class PolicyCatalog(GovernanceView):
    connected_apps: list[PolicyCatalogApp]
    tools: list[PolicyCatalogTool]
    # The GitHub App installation's repositories and the workspace's models.
    repositories: list[PolicyCatalogRepository]
    models: list[PolicyCatalogModel]
    # MOYAI_NETWORK_POLICY_ENFORCEMENT: whether restricted network policies are admitted on Modal.
    network_enforcement: Literal["off", "modal"]


class SecurityProfilesAdmin(GovernanceView):
    profiles: list[SecurityProfileView]
    defaults: SecurityProfileDefaults
    catalog: PolicyCatalog


class SessionProfileOption(GovernanceView):
    id: str
    name: str
    policy: PolicyView


class MandatoryProfile(GovernanceView):
    id: str
    name: str


class SessionProfileCatalog(GovernanceView):
    profiles: list[SessionProfileOption]
    default_profile_id: str
    mandatory: MandatoryProfile | None


class SessionSecurityPolicy(GovernanceView):
    policy: PolicyView


class NewSessionSecurityPolicy(GovernanceView):
    """What a new session would bind under a profile, with the mandatory policy applied."""

    policy: PolicyView
    # The model a session that does not ask for one starts on; None when the policy allows no enabled model.
    default_model: str | None


class SpendLimitView(GovernanceView):
    id: str
    kind: Literal["organization", "user-default", "session-default", "user"]
    subject: str
    # None is unlimited; zero blocks new paid requests.
    limit_usd: float | None
    revision: int
    updated_at: str | None
    updated_by: str
    # Month-to-date spend for "organization" and "user" rows; None for defaults,
    # usage awaiting cost recovery (which blocks it), or a caller without spend.read.
    used_usd: float | None


class SpendUsage(GovernanceView):
    organization_month_usd: float
    period_start: str
    # Finished requests awaiting cost recovery; each blocks every limited scope it counts toward.
    unknown_requests: int
    # Requests still running; they count once finished.
    in_flight_requests: int
    # Requests whose cost recovery cannot settle; excluded from limits, for review.
    unresolved_requests: int


class SpendLimitsAdmin(GovernanceView):
    limits: list[SpendLimitView]
    # None for a limit manager without spend.read.
    usage: SpendUsage | None
    can_manage: bool
