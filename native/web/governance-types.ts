// Settings → Governance UI types. Every backend payload type comes from the
// generated client (./generated/api); this module only derives UI state from it,
// so a backend rename fails the typecheck here instead of shipping `undefined`.
import type { ExportGovernanceAuditData, ListGovernanceAuditData, PolicyCatalogApp, PolicyView } from "./generated/api"

export type GitAccess = PolicyView["git_access"]
export type ConnectedApp = PolicyCatalogApp["id"]

/** Audit filter form state. Dates are whole UTC days (YYYY-MM-DD); blank means unfiltered. */
export type AuditFilters = { action: string; actor: string; resource_type: string; from: string; to: string }
/** GET /api/admin/governance/audit query: filters, cursor and page size. */
export type AuditQuery = NonNullable<ListGovernanceAuditData["query"]>
type AuditExportQuery = NonNullable<ExportGovernanceAuditData["query"]>
type AuditFilterKey = "action" | "actor" | "resource_type" | "after" | "before"
/** The filter parameters. The feed and the export must both accept every one of them. */
export type AuditFilterQuery = Pick<AuditQuery, AuditFilterKey> & Pick<AuditExportQuery, AuditFilterKey>
export type AuditExportFormat = NonNullable<AuditExportQuery["format"]>
