// Model and connection pickers follow the effective session security policy.
// These only narrow choices; admission on the server still decides.
import type { ConnectionView, OrganizationConnectionRepository, PolicyView } from "./generated/api"

type Limits = Pick<PolicyView, "connected_apps" | "git_access" | "repositories" | "models">

/** The enabled models a policy allows, in workspace order. Without a policy every model is offered. */
export function policyModels(models: readonly string[], policy?: Pick<PolicyView, "models"> | null): string[] {
  const allowed = policy?.models
  return allowed == null ? [...models] : models.filter(model => allowed.includes(model))
}

/**
 * The model to show and send. A model limit keeps the current choice while it
 * is allowed, otherwise uses the fallback, then the first allowed model, and
 * "" when none is allowed. Without a limit the current choice is kept.
 */
export function policyModel(models: readonly string[], policy: Pick<PolicyView, "models"> | null | undefined, current: string, fallback?: string | null): string {
  if (policy?.models == null) return current
  const allowed = policyModels(models, policy)
  if (allowed.includes(current)) return current
  return fallback && allowed.includes(fallback) ? fallback : allowed[0] ?? ""
}

/** Whether the policy allows this permanent GitHub repository ID; under a limit an unknown ID is refused. */
export function policyAdmitsRepository(policy: Pick<PolicyView, "repositories"> | null | undefined, repositoryId: number | null | undefined): boolean {
  return policy?.repositories == null || typeof repositoryId === "number" && policy.repositories.includes(repositoryId)
}

/** A connection row's permanent GitHub repository ID, or null. */
export function connectionRepository(row: Pick<ConnectionView, "policy">): number | null {
  const identity = row.policy.product?.repository_id
  return typeof identity === "number" && Number.isSafeInteger(identity) && identity > 0 ? identity : null
}

/** Whether the policy allows selecting this connection (ProductGovernance.admits_grant). */
export function policyAdmitsConnection(policy: Limits | null | undefined, row: Pick<ConnectionView, "kind" | "policy">): boolean {
  if (!policy) return true
  if (policy.connected_apps != null && !policy.connected_apps.some(app => app === row.kind)) return false
  if (row.kind !== "github") return true
  return policy.git_access !== "none" && policyAdmitsRepository(policy, connectionRepository(row))
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

/**
 * Whether a repository limit refuses this workflow repository: by its saved
 * permanent ID, otherwise by owner/name among the allowed repositories' last
 * known names. The server resolves the ID on save and checks it again.
 */
export function policyRefusesRepository(policy: Pick<PolicyView, "repositories"> | null | undefined, repositoryId: number | null | undefined, name: string, known: readonly Pick<OrganizationConnectionRepository, "id" | "full_name">[]): boolean {
  const allowed = policy?.repositories
  if (allowed == null) return false
  if (typeof repositoryId === "number") return !allowed.includes(repositoryId)
  const wanted = name.trim().toLowerCase()
  return Boolean(wanted) && !known.some(repository => allowed.includes(repository.id) && repository.full_name.toLowerCase() === wanted)
}
