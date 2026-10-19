// Settings → Governance (product mode). Loaded lazily by the Settings shell so
// the shell never depends on these pages at startup.
import type { SettingsUser } from "./settings"
import { can } from "./permissions"
import { RolesPage } from "./governance-roles"
import { ProvisioningPage } from "./governance-provisioning"
import { SecurityPoliciesPage } from "./governance-policies"
import { SpendLimitsPage } from "./governance-spend"
import { AuditLogPage } from "./governance-audit"

export function GovernancePage({ page, user }: { page: string; user: SettingsUser }) {
  return <div className="ns-gov">{page === "roles" ? <RolesPage />
    : page === "provisioning" ? <ProvisioningPage canManageRoles={can(user, "roles.manage")} />
      : page === "security-policies" ? <SecurityPoliciesPage />
        : page === "spend-limits" ? <SpendLimitsPage canManage={can(user, "spend.manage")} />
          : page === "audit-log" ? <AuditLogPage /> : null}</div>
}

export * from "./governance-data"
export { RoleRows, AssignmentRows, GroupGrantRows, RoleEditor } from "./governance-roles"
export { TokenRows, DirectoryUserRows, DirectoryGroupRows, TokenDialog, tokenStatus } from "./governance-provisioning"
export { ProfileRows, PolicyEditor } from "./governance-policies"
export { SpendSummary, OverrideRows } from "./governance-spend"
export { AuditRows } from "./governance-audit"
export { ActivityList, AuditDetails, CopyField } from "./governance-shared"
