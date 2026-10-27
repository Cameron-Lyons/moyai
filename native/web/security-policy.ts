// Model and connection pickers follow the effective session security policy.
// These only narrow choices; admission on the server still decides.
import type { ConnectionView, OrganizationConnectionRepository, PolicyView } from "./generated/api"

type Limits = Pick<PolicyView, "connected_apps" | "git_access" | "repositories" | "models">

/** The enabled models a policy allows, in workspace order. Without a policy every model is offered. */
export function policyModels(models: readonly string[], policy?: Pick<PolicyView, "models"> | null): string[] {
  const allowed = policy?.models
  return allowed == null ? [...models] : models.filter(model => allowed.includes(model))
}

/** The model to show and send: the current choice while allowed, else the fallback, else the first allowed model, else "". */
export function policyModel(models: readonly string[], policy: Pick<PolicyView, "models"> | null | undefined, current: string, fallback?: string | null): string {
  if (policy?.models == null) return current
  const allowed = policyModels(models, policy)
  if (allowed.includes(current)) return current
  return fallback && allowed.includes(fallback) ? fallback : allowed[0] ?? ""
}

/** Whether the policy allows selecting this connection (ProductGovernance.admits_grant); under a repository limit a GitHub row needs its listed permanent ID. */
export function policyAdmitsConnection(policy: Limits | null | undefined, row: Pick<ConnectionView, "kind" | "policy">): boolean {
  if (!policyAdmitsApp(policy, row.kind)) return false
  // Read the row's repository only under a repository limit: older servers send rows without a policy.
  if (row.kind !== "github" || policy?.repositories == null) return true
  const identity = row.policy?.product?.repository_id
  return typeof identity === "number" && policy.repositories.includes(identity)
}

/** Whether the policy allows a workflow to select this connected app (ProductGovernance.workflow). */
export function policyAdmitsApp(policy: Limits | null | undefined, app: string): boolean {
  if (!policy) return true
  if (policy.connected_apps != null && !policy.connected_apps.some(allowed => allowed === app)) return false
  return app !== "github" || policy.git_access !== "none" && (policy.repositories == null || policy.repositories.length > 0)
}

/** owner/name of a GitHub repository URL, or the trimmed text when it is not one. */
export function githubRepositoryName(value: string): string {
  const text = value.trim()
  return /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+\/[^/\s]+?)(?:\.git)?\/?$/i.exec(text)?.[1] ?? text
}

/** Whether a repository limit refuses a workflow repository: by saved ID, else by owner/name among the allowed repositories' known names. The server checks again on save. */
export function policyRefusesRepository(policy: Pick<PolicyView, "repositories"> | null | undefined, repositoryId: number | null | undefined, name: string, known: readonly Pick<OrganizationConnectionRepository, "id" | "full_name">[]): boolean {
  const allowed = policy?.repositories
  if (allowed == null) return false
  if (typeof repositoryId === "number") return !allowed.includes(repositoryId)
  const wanted = name.trim().toLowerCase()
  return Boolean(wanted) && !known.some(repository => allowed.includes(repository.id) && repository.full_name.toLowerCase() === wanted)
}
