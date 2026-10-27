// Settings → Governance (product mode). Loaded lazily by the Settings shell so
// the shell never depends on these pages at startup.
import type { SettingsUser } from "./settings"
import { can } from "./permissions"
import { RolesPage } from "./governance-roles"
import { ProvisioningPage } from "./governance-provisioning"
import { ServiceAccountsPage } from "./governance-service-accounts"
import { SecurityPoliciesPage } from "./governance-policies"
import { SpendLimitsPage } from "./governance-spend"
import { AuditLogPage } from "./governance-audit"
import "./governance.css"

export function GovernancePage({ page, user }: { page: string; user: SettingsUser }) {
  return <div className="ns-gov">{page === "roles" ? <RolesPage />
    : page === "provisioning" ? <ProvisioningPage canManageRoles={can(user, "roles.manage")} />
      : page === "service-accounts" ? <ServiceAccountsPage />
      : page === "security-policies" ? <SecurityPoliciesPage />
        : page === "spend-limits" ? <SpendLimitsPage canManage={can(user, "spend.manage")} />
          : page === "audit-log" ? <AuditLogPage /> : null}</div>
}

// Re-exported for tests/test_native_governance.cjs.
export * from "./governance-data"
export { RoleRows } from "./governance-roles"
export { TokenRows, DirectoryUserRows } from "./governance-provisioning"
export { KeyRows } from "./governance-service-accounts"
export { ProfileRows } from "./governance-policies"
export { SpendSummary, OverrideRows, TierRows, DeletedTierRows } from "./governance-spend"
export { AuditRows } from "./governance-audit"
