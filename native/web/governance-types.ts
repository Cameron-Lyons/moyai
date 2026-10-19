// Enterprise governance API contract (product mode). The backend implements
// these shapes exactly; the canonical governance API documents status codes.
// Errors always use FastAPI's {detail: string}. Times are UTC ISO-8601 strings.

export type Permission = string

/** /api/me additions. `permissions` is present in both modes. */
export type AccessRole = { id: string; name: string }
export type MeGovernance = { permissions?: Permission[]; access_role?: AccessRole | null }

/** GET /api/permissions */
export type PermissionInfo = { id: Permission; label: string; description: string; group: string }
export type PermissionCatalog = {
  permissions: Permission[]
  catalog: PermissionInfo[]
  builtin_roles: { admin: Permission[]; member: Permission[] }
}

/** GET /api/admin/roles */
export type Role = {
  id: string; name: string; description: string; permissions: Permission[]
  revision: number; archived: boolean; updated_at: string; updated_by: string
}
export type RoleAssignment = {
  email: string; role_id: string; role_name: string; revision: number
  /** Revision of the person's built-in role (user_roles) when this row was read. */
  role_revision: number; updated_at: string; updated_by: string
}
export type GroupRole = {
  group_id: string; group_name: string; role_id: string | null; role_name: string | null
  revision: number; updated_at: string; updated_by: string
}
export type DirectoryGroup = { id: string; display_name: string; member_count: number }
export type RolesAdmin = {
  roles: Role[]; assignments: RoleAssignment[]; group_roles: GroupRole[]; groups: DirectoryGroup[]
  /** Permissions the caller may grant; null for a built-in administrator (unrestricted). */
  grantable: Permission[] | null
  builtin_admin: boolean
}
/** POST /api/admin/roles (201 → Role) */
export type CreateRoleBody = { id: string; name: string; description: string; permissions: Permission[] }
/** PUT /api/admin/roles/{role_id} (200 → Role) */
export type UpdateRoleBody = { name: string; description: string; permissions: Permission[]; revision: number }
/** PUT /api/admin/role-assignments (200 → RoleAssignment). role_id "member" removes a custom role. */
export type AssignmentBody = { email: string; role_id: string; revision: number; role_revision: number | null }
/** PUT /api/admin/group-roles/{group_id} (200 → GroupRole) */
export type GroupRoleBody = { role_id: string | null; revision: number }

/** Governance audit entry, shared by the audit feed and SCIM activity. */
export type AuditDetailValue = string | number | boolean | null | string[]
export type AuditEntry = {
  id: string
  source: "governance" | "user_roles" | "connections" | "credentials"
  action: string; actor: string; resource_type: string; resource_id: string
  details: Record<string, AuditDetailValue>
  created_at: string
}

/** GET /api/admin/scim?cursor=&limit= */
export type ScimUser = {
  id: string; user_name: string; display_name: string; active: boolean; external_id: string
  groups_count: number; updated_at: string
}
export type ScimGroup = { id: string; display_name: string; member_count: number; role_id: string | null; role_name: string | null }
export type ScimToken = {
  id: string; label: string; prefix: string; created_at: string; created_by: string
  last_used_at: string | null; revoked_at: string | null
}
export type ScimAdmin = {
  base_url: string
  users: { items: ScimUser[]; next_cursor: string | null }
  groups: ScimGroup[]
  tokens: ScimToken[]
  activity: AuditEntry[]
  /** Only a built-in administrator can create provisioning tokens. */
  can_create_tokens: boolean
}
/** POST /api/admin/scim/tokens body {label} → 201. `token` is returned once and never again. */
export type CreatedScimToken = { id: string; label: string; prefix: string; created_at: string; token: string }

/** Security profiles. null = unrestricted, [] = nothing allowed, list = only these. */
export type GitAccess = "write" | "read" | "none"
export type ProfilePolicy = {
  connected_apps: string[] | null
  tools: string[] | null
  git_access: GitAccess
  network_domains: string[] | null
}
export type SecurityProfile = {
  id: string; name: string; enabled: boolean; revision: number; policy: ProfilePolicy
  updated_at: string; updated_by: string
}
export type ProfileDefaults = {
  default_profile_id: string; mandatory_profile_id: string; revision: number
  updated_at: string; updated_by: string
}
/** GET /api/admin/security-profiles */
export type SecurityProfilesAdmin = {
  profiles: SecurityProfile[]
  defaults: ProfileDefaults
  catalog: {
    connected_apps: { id: string; label: string }[]
    tools: { id: string; label: string; group: string }[]
  }
}
/** POST /api/admin/security-profiles (201) and PUT /api/admin/security-profiles/{id} (200) → SecurityProfile */
export type SaveProfileBody = { name: string; enabled: boolean; policy: ProfilePolicy; revision: number }
/** PUT /api/admin/security-profiles/defaults → ProfileDefaults. "" clears a selection. */
export type DefaultsBody = { default_profile_id: string; mandatory_profile_id: string; revision: number }
/** GET /api/security-profiles (security.manage): enabled profiles only. */
export type SessionProfileCatalog = {
  profiles: { id: string; name: string; policy: ProfilePolicy }[]
  default_profile_id: string
  mandatory: { id: string; name: string } | null
}

/** Spend limits. limit_usd null = no limit, 0 = blocked. */
export type SpendLimitKind = "organization" | "user-default" | "session-default" | "user"
export type SpendLimit = {
  id: string; kind: SpendLimitKind; subject: string; limit_usd: number | null; revision: number
  updated_at: string; updated_by: string
  /** Month-to-date spend for kind "organization" and "user"; null for defaults. */
  used_usd: number | null
}
/** GET /api/admin/spend-limits and the PUT response. The three singleton rows are always present. */
export type SpendLimitsAdmin = {
  limits: SpendLimit[]
  usage: { organization_month_usd: number; period_start: string; unknown_requests?: number }
  can_manage: boolean
}
/** PUT /api/admin/spend-limits. revision 0 creates a row. */
export type SpendLimitChange = { id: string; limit_usd: number | null; revision: number }
export type SpendLimitsBody = { changes: SpendLimitChange[] }
/** GET /api/spend/limits (spend.personal) */
export type PersonalSpendLimits = {
  period_start: string
  organization: { limit_usd: number; used_usd: number } | null
  user: { limit_usd: number; used_usd: number } | null
  session_limit_usd: number | null
}

/** GET /api/admin/governance/audit */
export type AuditPage = {
  entries: AuditEntry[]
  next_cursor: string | null
  /** Static lists of known filter values (not derived from the returned page). */
  facets: { actions: string[]; resource_types: string[] }
}
export type AuditFilters = { action: string; actor: string; resource_type: string; from: string; to: string }

/** /api/settings/users product rows gain governance fields. */
export type DirectoryAccess = {
  /** Custom direct role; null when the person uses a built-in role only. */
  access_role?: { id: string; name: string; revision: number } | null
  /** False when the directory (SCIM) deactivated the person. */
  active?: boolean
}
/** PUT /api/settings/users/role optional additions when replacing a custom role. */
export type BuiltinRoleBody = {
  email: string; role: "admin" | "member"; revision: number
  replace_custom_role?: true; access_revision?: number
}
