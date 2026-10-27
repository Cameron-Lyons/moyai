// Pure request builders and formatters for Settings → Governance. Every
// function validates locally with plain-language errors; the server remains
// authoritative and re-validates every field.
import type {
  AuditEntry, EffectiveSpendLimit, ExportGovernanceAuditData, GovernanceGroupRole, GovernanceRole, GovernanceRoleAssignment, GroupRoleChange, PermissionInfo, PersonalSpendStatus, PolicyCatalog, PolicyCatalogRepository,
  PolicyView, ProfileDefaults, ProfilePolicy, RoleAssignment, RoleCreate, RoleUpdate, SaveProfile, SecurityProfileView, ServiceAccountCreate, ServiceAccountKey,
  ServiceAccountUpdate, ServiceAccountView, ServiceKeyCreate, SpendGroupLimitView, SpendLimitChange, SpendLimitView,
} from "./generated/api"
import type { AuditExportFormat, AuditFilterQuery, AuditFilters, AuditQuery, ConnectedApp, GitAccess } from "./governance-types"

export const ROLE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/
const EMAIL_PATTERN = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z0-9-]+$/
const BUILTIN_ROLE_IDS = new Set(["admin", "member"])

export function normalizeEmail(value: string): string {
  const email = value.trim().toLowerCase()
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) throw new Error("Enter a work email address, such as name@example.com.")
  return email
}

/** Suggest a stable role ID from its display name. */
export function roleIdFromName(name: string): string {
  let id = name.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64).replace(/-+$/g, "")
  if (id && !/^[a-z]/.test(id)) id = `role-${id}`.slice(0, 64).replace(/-+$/g, "")
  if (BUILTIN_ROLE_IDS.has(id)) id = `${id}-custom`
  return id
}

export type RoleDraft = { id: string; name: string; description: string; permissions: string[] }
/** An edit sends the displayed revision and never the role ID; creation sends the ID. */
export function roleBody(draft: RoleDraft, existing: GovernanceRole, catalog: readonly PermissionInfo[]): RoleUpdate
export function roleBody(draft: RoleDraft, existing: undefined, catalog: readonly PermissionInfo[]): RoleCreate
export function roleBody(draft: RoleDraft, existing: GovernanceRole | undefined, catalog: readonly PermissionInfo[]): RoleCreate | RoleUpdate {
  const name = draft.name.trim(), description = draft.description.trim()
  if (name.length < 2 || name.length > 100) throw new Error("Use a role name between 2 and 100 characters.")
  if (description.length > 500) throw new Error("Keep the description to 500 characters or fewer.")
  const known = new Set(catalog.map(item => item.id))
  const permissions = [...new Set(draft.permissions)].sort()
  if (permissions.some(permission => !known.has(permission))) throw new Error("Choose permissions from the permission catalog.")
  if (existing) return { name, description, permissions, revision: existing.revision }
  const id = draft.id.trim()
  if (!ROLE_ID_PATTERN.test(id) || id.length > 64) throw new Error("Use a role ID with lowercase letters, numbers and single hyphens, starting with a letter.")
  if (BUILTIN_ROLE_IDS.has(id)) throw new Error("Built-in role IDs cannot be reused. Choose another role ID.")
  return { id, name, description, permissions }
}

/** Group the catalog by its server-provided group, preserving catalog order. */
export function permissionGroups(catalog: readonly PermissionInfo[]): { group: string; items: PermissionInfo[] }[] {
  const groups = new Map<string, PermissionInfo[]>()
  for (const item of catalog) groups.set(item.group || "Other", [...groups.get(item.group || "Other") ?? [], item])
  return [...groups].map(([group, items]) => ({ group, items }))
}
export function permissionLabel(catalog: readonly PermissionInfo[], id: string): string {
  return catalog.find(item => item.id === id)?.label || id
}

export function assignmentBody(email: string, roleId: string, existing: GovernanceRoleAssignment | undefined): RoleAssignment {
  if (!roleId) throw new Error("Choose a role.")
  if (roleId === "admin") throw new Error("Grant administrator access on the Users page.")
  return existing
    ? { email: existing.email, role_id: roleId, revision: existing.revision, role_revision: existing.role_revision }
    : { email: normalizeEmail(email), role_id: roleId, revision: 0, role_revision: null }
}
export function groupRoleBody(roleId: string, existing: GovernanceGroupRole | undefined): GroupRoleChange {
  if (roleId === "admin" || roleId === "member") throw new Error("Choose a custom role, or no additional role.")
  return { role_id: roleId || null, revision: existing?.revision ?? 0 }
}

/** Whether archiving would leave directly assigned people without permissions. */
export function roleUsage(role: GovernanceRole, assignments: readonly GovernanceRoleAssignment[], groups: readonly GovernanceGroupRole[]) {
  return { people: assignments.filter(row => row.role_id === role.id).length, groups: groups.filter(row => row.role_id === role.id).length }
}

// Security policies -----------------------------------------------------------

export type ScopeMode = "all" | "selected" | "none"
export type PolicyDraft = {
  name: string; enabled: boolean; git_access: GitAccess
  apps: ScopeMode; app_ids: ConnectedApp[]; tools: ScopeMode; tool_ids: string[]
  network: "all" | "listed" | "none"; domains: string
  repositories: ScopeMode; repository_ids: number[]; models: ScopeMode; model_ids: string[]
}
const modeOf = (value: readonly unknown[] | null): ScopeMode => value === null ? "all" : value.length ? "selected" : "none"
export function policyDraft(profile?: SecurityProfileView): PolicyDraft {
  const policy: PolicyView = profile?.policy ?? { connected_apps: null, tools: null, git_access: "write", network_domains: null, repositories: null, models: null }
  return {
    name: profile?.name ?? "", enabled: profile?.enabled ?? true, git_access: policy.git_access,
    apps: modeOf(policy.connected_apps), app_ids: policy.connected_apps ?? [],
    tools: modeOf(policy.tools), tool_ids: policy.tools ?? [],
    network: policy.network_domains === null ? "all" : policy.network_domains.length ? "listed" : "none",
    domains: (policy.network_domains ?? []).join("\n"),
    repositories: modeOf(policy.repositories), repository_ids: policy.repositories ?? [],
    models: modeOf(policy.models), model_ids: policy.models ?? [],
  }
}
/** A saved repository keeps its ID as its label once it leaves the catalog. */
export function repositoryLabel(repositories: readonly PolicyCatalogRepository[], id: number): string {
  return repositories.find(repository => repository.id === id)?.label ?? `Repository ${id}`
}

/** The network choice's effect, then how this deployment enforces it (MOYAI_NETWORK_POLICY_ENFORCEMENT). */
export function networkHint(network: PolicyDraft["network"], enforcement: PolicyCatalog["network_enforcement"]): string {
  const choice = network === "all" ? "No outbound restriction is applied."
    : network === "none" ? "The machine cannot open outbound connections. Package installs and downloads will fail."
    : "Only these hostnames are reachable."
  if (enforcement === "off") return `${choice} Network enforcement is off in this deployment, so sessions with a restricted network policy are refused before they start.`
  if (network === "all") return choice
  return `${choice} Enforced on Modal computers for HTTPS (port 443) by hostname; plain HTTP, SSH and other ports are blocked. `
    + "DNS lookups are not restricted, and allowing a shared CDN domain can allow other sites it serves. "
    + "Lambda computers refuse restricted policies. A running computer started under a wider policy must restart."
}

const HOST_LABEL = /^[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?$/
/** Split pasted domains and reject URLs, ports, paths, IP addresses and bare wildcards. */
export function parseDomains(text: string): { domains: string[]; invalid: string[] } {
  const domains = new Set<string>(), invalid: string[] = []
  for (const raw of text.split(/[\s,]+/)) {
    const value = raw.trim().toLowerCase().replace(/\.$/, "")
    if (!value) continue
    const host = value.startsWith("*.") ? value.slice(2) : value
    const labels = host.split(".")
    const ok = !/[/:@?#\[\]\\]/.test(value) && !host.includes("*") && host.length <= 253 && labels.length >= 2
      && labels.every(label => HOST_LABEL.test(label)) && !/^\d+$/.test(labels[labels.length - 1])
    if (ok) domains.add(value); else invalid.push(raw.trim())
  }
  return { domains: [...domains].sort(), invalid }
}

export function policyBody(draft: PolicyDraft, existing: SecurityProfileView | undefined): SaveProfile {
  const name = draft.name.trim()
  if (!name || name.length > 80) throw new Error("Use a policy name between 1 and 80 characters.")
  if (!["write", "read", "none"].includes(draft.git_access)) throw new Error("Choose a Git access level.")
  const scoped = <T extends string | number>(mode: ScopeMode, ids: readonly T[], noun: string, none: string): T[] | null => {
    if (mode === "all") return null
    if (mode === "none") return []
    const selected = [...new Set(ids)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0)
    if (!selected.length) throw new Error(`Select at least one ${noun}, or choose “${none}”.`)
    return selected
  }
  let network_domains: string[] | null = null
  if (draft.network === "none") network_domains = []
  else if (draft.network === "listed") {
    const parsed = parseDomains(draft.domains)
    if (parsed.invalid.length) throw new Error(`Use hostnames such as registry.npmjs.org or *.example.com. Check: ${parsed.invalid.slice(0, 3).join(", ")}.`)
    if (!parsed.domains.length) throw new Error("Add at least one domain, or choose “Block all outbound network access”.")
    if (parsed.domains.length > 200) throw new Error("List at most 200 domains.")
    network_domains = parsed.domains
  }
  // Every field is sent: the server refuses an update that omits saved repository or model limits.
  const policy = {
    connected_apps: scoped(draft.apps, draft.app_ids, "app", "No connected apps"),
    tools: scoped(draft.tools, draft.tool_ids, "tool", "No tools"),
    git_access: draft.git_access, network_domains,
    repositories: scoped(draft.repositories, draft.repository_ids, "repository", "No repositories"),
    models: scoped(draft.models, draft.model_ids, "model", "No models"),
  } satisfies Required<ProfilePolicy>
  return { name, enabled: draft.enabled, policy, revision: existing?.revision ?? 0 }
}

export function defaultsBody(defaultId: string, mandatoryId: string, revision: number, profiles: readonly SecurityProfileView[]): ProfileDefaults {
  const enabled = new Set(profiles.filter(profile => profile.enabled).map(profile => profile.id))
  for (const id of [defaultId, mandatoryId]) if (id && !enabled.has(id)) throw new Error("Choose an enabled security policy.")
  return { default_profile_id: defaultId, mandatory_profile_id: mandatoryId, revision }
}

const gitLabels: Record<GitAccess, string> = { write: "Read and write", read: "Read only", none: "No Git access" }
export type SummaryLabels = { app?: (id: ConnectedApp) => string; repository?: (id: number) => string; model?: (id: string) => string }
export function policySummary(policy: PolicyView, labels: SummaryLabels = {}) {
  const { app = id => id, repository = id => `Repository ${id}`, model = id => id } = labels
  const list = <T,>(value: T[] | null, all: string, none: string, many: (count: number) => string, names?: (ids: T[]) => string) =>
    value === null ? all : !value.length ? none : names && value.length <= 3 ? names(value) : many(value.length)
  return {
    apps: list(policy.connected_apps, "All connected apps", "No connected apps", count => `${count} apps`, ids => ids.map(app).join(", ")),
    tools: list(policy.tools, "All tools", "No tools", count => `${count} tools`, ids => ids.join(", ")),
    git: gitLabels[policy.git_access] ?? policy.git_access,
    network: list(policy.network_domains, "Unrestricted network", "No outbound network", count => `${count} domains`, ids => ids.join(", ")),
    repositories: list(policy.repositories, "All repositories", "No repositories", count => `${count} repositories`, ids => ids.map(repository).join(", ")),
    models: list(policy.models, "All models", "No models", count => `${count} models`, ids => ids.map(model).join(", ")),
  }
}

// Spend limits ----------------------------------------------------------------

const usdFormat = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" })
export const usd = (value: number | null | undefined) => typeof value === "number" && Number.isFinite(value) ? usdFormat.format(value) : "—"
export const limitText = (value: number | null) => value === null ? "No limit" : value === 0 ? "Blocked ($0.00)" : usd(value)

/** Blank means no limit; 0 blocks model use. */
export function parseUsd(text: string): number | null {
  const value = text.trim().replace(/^\$/, "").replace(/,/g, "")
  if (!value) return null
  if (!/^\d+(?:\.\d{1,2})?$/.test(value)) throw new Error("Enter a dollar amount with up to two decimal places, or leave it blank for no limit.")
  const amount = Number(value)
  if (amount > 1_000_000) throw new Error("Use a limit of $1,000,000 or less.")
  return amount
}
export const usdInput = (value: number | null) => value === null ? "" : value.toFixed(2)

/** Only changed rows are sent, each with the revision that was displayed. */
export function spendChanges(limits: readonly SpendLimitView[], drafts: Record<string, string>): SpendLimitChange[] {
  const changes: SpendLimitChange[] = []
  for (const [id, text] of Object.entries(drafts)) {
    const row = limits.find(limit => limit.id === id)
    if (!row) continue
    const limit_usd = parseUsd(text)
    if (limit_usd !== row.limit_usd) changes.push({ id, limit_usd, revision: row.revision })
  }
  return changes
}
export function overrideChange(email: string, text: string, existing: SpendLimitView | undefined): SpendLimitChange {
  if (existing) return { id: existing.id, limit_usd: parseUsd(text), revision: existing.revision }
  return { id: `user:${normalizeEmail(email)}`, limit_usd: parseUsd(text), revision: 0 }
}
/** A directory group's tier: a new tier sends revision 0, an edit the revision that was displayed. */
export function tierChange(groupId: string, text: string, existing: SpendGroupLimitView | undefined): SpendLimitChange {
  if (existing) return { id: existing.id, limit_usd: parseUsd(text), revision: existing.revision }
  if (!/^[0-9a-f]{32}$/.test(groupId)) throw new Error("Choose a directory group.")
  return { id: `group:${groupId}`, limit_usd: parseUsd(text), revision: 0 }
}
/** Where a person's monthly limit comes from: override, else their most permissive group tier, else the default. */
export function limitSourceText(source: EffectiveSpendLimit["source"], groupName: string): string {
  if (source === "override") return "Per-person override"
  if (source === "group") return groupName ? `${groupName} group tier` : "Directory group tier"
  return "Default monthly limit"
}

const resetDay = (value: string) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleDateString(undefined, { month: "long", day: "numeric", timeZone: "UTC" }) : "the first day of next month"
export type SpendNotice = { tone: "warning" | "reached" | "pending"; text: string }
/** The personal budget notice: at two-thirds of the monthly limit, at a limit, or while a cost a limit waits on is recorded. */
export function spendNotice(status: PersonalSpendStatus): SpendNotice | null {
  const personal = status.personal, resets = resetDay(status.resets_at)
  if (personal?.level === "reached") return { tone: "reached", text: personal.limit_usd === 0
    ? "Your model use is blocked by a $0 monthly limit. Ask a spend manager to raise it."
    : `Your ${usd(personal.limit_usd)} monthly model budget is used up. New model requests are refused until ${resets} (UTC) or until a spend manager raises your limit.` }
  if (status.organization_reached) return { tone: "reached", text: `The organization's monthly model budget is used up. New model requests are refused until ${resets} (UTC) or until a spend manager raises it.` }
  if (personal?.level === "pending" || status.organization_pending) return { tone: "pending", text: "An earlier model request's cost is still being recorded. New model requests may be refused for a few minutes until it is." }
  if (personal?.level === "warning") return { tone: "warning", text: `You have used ${usd(personal.used_usd)} of your ${usd(personal.limit_usd)} monthly model budget. It resets on ${resets} (UTC).` }
  return null
}

// Audit log -------------------------------------------------------------------

export const emptyAuditFilters: AuditFilters = { action: "", actor: "", resource_type: "", from: "", to: "" }
const DAY = 86_400_000
const dateValue = (value: string) => /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(`${value}T00:00:00Z`)) ? Date.parse(`${value}T00:00:00Z`) : NaN

/** Filters shared by the audit feed and its export (dates are whole UTC days). */
export function auditQuery(filters: AuditFilters): AuditFilterQuery {
  const query: AuditFilterQuery = {}
  if (filters.action) query.action = filters.action
  if (filters.actor.trim()) query.actor = filters.actor.trim().toLowerCase()
  if (filters.resource_type) query.resource_type = filters.resource_type
  const from = filters.from ? dateValue(filters.from) : NaN, to = filters.to ? dateValue(filters.to) : NaN
  if (filters.from && !Number.isFinite(from)) throw new Error("Enter the start date as YYYY-MM-DD.")
  if (filters.to && !Number.isFinite(to)) throw new Error("Enter the end date as YYYY-MM-DD.")
  if (Number.isFinite(from) && Number.isFinite(to)) {
    if (from > to) throw new Error("Choose a start date on or before the end date.")
    if ((to + DAY - from) / DAY > 100) throw new Error("Choose a date range of at most 100 days.")
  }
  if (Number.isFinite(from)) query.after = new Date(from).toISOString().replace(".000Z", "Z")
  if (Number.isFinite(to)) query.before = new Date(to + DAY).toISOString().replace(".000Z", "Z")
  return query
}
/** One page of the audit feed (listGovernanceAudit). */
export function auditPageQuery(filters: AuditFilters, cursor?: string | null): AuditQuery {
  return { ...auditQuery(filters), limit: 50, ...(cursor ? { cursor } : {}) }
}
// The export is a file download (apiDownload), not a generated JSON call; its
// path and parameters are still checked against the generated operation.
const AUDIT_EXPORT: ExportGovernanceAuditData["url"] = "/api/admin/governance/audit/export"
export function auditExportPath(filters: AuditFilters, format: AuditExportFormat): string {
  const query: NonNullable<ExportGovernanceAuditData["query"]> = { ...auditQuery(filters), format }
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== null) params.set(key, String(value))
  return `${AUDIT_EXPORT.slice("/api".length)}?${params}`
}
/** "role_assignment.updated" → "Role assignment updated". */
const ACRONYMS: Record<string, string> = { scim: "SCIM", usd: "USD", id: "ID", sso: "SSO", aws: "AWS", ai: "AI" }
export function actionLabel(action: string): string {
  const text = action.replace(/[._-]+/g, " ").trim().split(/\s+/).map(word => ACRONYMS[word.toLowerCase()] ?? word).join(" ")
  return text ? text[0].toUpperCase() + text.slice(1) : "Change recorded"
}
/** Filter labels for resource types; others read as their words ("scim_user" → "scim user"). */
const RESOURCE_TYPE_LABELS: Record<string, string> = {
  sign_in: "Sign-in", session: "Sessions", message: "Messages", policy: "Policy denials", automation: "Automations",
}
export function resourceTypeLabel(value: string): string {
  return RESOURCE_TYPE_LABELS[value] ?? value.replace(/_/g, " ")
}
/** An activity row's outcome when it is not a success: the server folds it into details. */
export function auditOutcome(entry: Pick<AuditEntry, "details">): "denied" | "failed" | null {
  const outcome = entry.details?.outcome
  return outcome === "denied" || outcome === "failed" ? outcome : null
}
export function detailText(value: unknown): string {
  if (value === null || value === undefined || value === "") return "None"
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : "None"
  if (typeof value === "object") return JSON.stringify(value)
  return String(value)
}

// Service accounts ------------------------------------------------------------

type KeyLifetime = NonNullable<ServiceKeyCreate["expires_in_days"]>
/** Every API key expires; these are the only lifetimes the server accepts. */
export const EXPIRY_CHOICES: readonly KeyLifetime[] = [30, 90, 180, 365]
export const DEFAULT_EXPIRY: KeyLifetime = 90
const EXPIRY_WARNING_DAYS = 14

export type KeyState = { label: "Active" | "Expired" | "Revoked"; tone: "success" | "warning" | "danger" | "neutral"; note: string }
/** A key's status in words, with an expiry warning; color only reinforces it. */
export function keyState(key: ServiceAccountKey, now = Date.now()): KeyState {
  if (key.status === "revoked") return { label: "Revoked", tone: "neutral", note: "" }
  const at = Date.parse(key.expires_at), days = Math.floor((at - now) / DAY)
  if (key.status === "expired" || !Number.isFinite(at) || days < 0) return { label: "Expired", tone: "danger", note: "" }
  if (days < EXPIRY_WARNING_DAYS) return { label: "Active", tone: "warning", note: days === 0 ? "Expires today" : `Expires in ${days === 1 ? "1 day" : `${days} days`}` }
  return { label: "Active", tone: "success", note: "" }
}
export const activeKeys = (account: ServiceAccountView) => account.keys.filter(key => key.status === "active").length
export const canIssueKey = (account: ServiceAccountView, maxActiveKeys: number) => account.active && activeKeys(account) < maxActiveKeys

export type ServiceAccountDraft = { name: string; description: string; permissions: string[] }
/** An edit sends the displayed revision and keeps the account's state; creation sends only the account. */
export function serviceAccountBody(draft: ServiceAccountDraft, existing: ServiceAccountView, ceiling: readonly string[]): ServiceAccountUpdate
export function serviceAccountBody(draft: ServiceAccountDraft, existing: undefined, ceiling: readonly string[]): ServiceAccountCreate
export function serviceAccountBody(draft: ServiceAccountDraft, existing: ServiceAccountView | undefined, ceiling: readonly string[]): ServiceAccountCreate | ServiceAccountUpdate {
  const name = draft.name.trim(), description = draft.description.trim()
  if (name.length < 2 || name.length > 80) throw new Error("Use a name between 2 and 80 characters.")
  if (description.length > 500) throw new Error("Keep the description to 500 characters or fewer.")
  const permissions = [...new Set(draft.permissions)].sort()
  if (permissions.some(permission => !ceiling.includes(permission))) throw new Error("Service accounts can hold only the permissions listed.")
  if (!permissions.length) throw new Error("Choose at least one permission.")
  return existing ? { name, description, permissions, active: existing.active, revision: existing.revision } : { name, description, permissions }
}
/** The account at its displayed revision with only its active state changed. */
export function serviceAccountState(account: ServiceAccountView, active: boolean): ServiceAccountUpdate {
  return { name: account.name, description: account.description, permissions: account.permissions, active, revision: account.revision }
}
export function serviceKeyBody(label: string, days: number): ServiceKeyCreate {
  const value = label.trim()
  if (!value || value.length > 80) throw new Error("Use a label between 1 and 80 characters.")
  const expires_in_days = EXPIRY_CHOICES.find(choice => choice === days)
  if (expires_in_days === undefined) throw new Error("Choose an expiry of 30, 90, 180 or 365 days.")
  return { label: value, expires_in_days }
}
/** A one-line collector request for the audit export; the key stays in an environment variable. */
export function collectorCommand(origin: string): string {
  return `curl --fail -G -H "Authorization: Bearer $MOYAI_API_KEY" -d format=ndjson "${origin.replace(/\/+$/, "")}${AUDIT_EXPORT}"`
}
