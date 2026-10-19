// Permission checks shared by navigation, Settings and Home. /api/me returns
// `permissions` in both modes; older servers fall back to the built-in sets.
export const ALL_PERMISSIONS = [
  "workspace.read", "sessions.read", "sessions.create", "sessions.manage",
  "connections.read", "connections.write", "connections.manage", "automations.read", "automations.manage",
  "environments.read", "skills.read", "skills.manage", "skills.publish",
  "memory.read", "memory.manage", "credentials.read", "credentials.manage", "credentials.publish",
  "users.read", "users.manage", "roles.manage", "scim.manage", "spend.personal", "spend.read", "spend.manage",
  "runtime.manage", "security.manage", "audit.read",
] as const
export const MEMBER_PERMISSIONS: readonly string[] = [
  "workspace.read", "sessions.read", "sessions.create", "sessions.manage", "connections.read", "connections.write",
  "automations.read", "automations.manage", "environments.read", "skills.read", "skills.manage",
  "memory.read", "memory.manage", "credentials.read", "credentials.manage", "spend.personal",
]

export type PermissionSubject = { role: string; permissions?: readonly string[] | null }

export function permissionsOf(subject: PermissionSubject): readonly string[] {
  if (Array.isArray(subject.permissions)) return subject.permissions
  return subject.role === "admin" ? ALL_PERMISSIONS : MEMBER_PERMISSIONS
}
export function can(subject: PermissionSubject, permission: string): boolean {
  return permissionsOf(subject).includes(permission)
}
/** Stable signature for keys that must reset protected state when access changes. */
export function permissionKey(subject: PermissionSubject): string {
  return [...permissionsOf(subject)].sort().join(",")
}

/** Settings pages that require a permission; other pages are available to every signed-in person. */
export const PAGE_PERMISSIONS: Readonly<Record<string, string>> = {
  users: "users.read", performance: "runtime.manage", usage: "spend.read",
  roles: "roles.manage", provisioning: "scim.manage", "security-policies": "security.manage",
  "spend-limits": "spend.read", "audit-log": "audit.read",
}
export function canOpenPage(subject: PermissionSubject, page: string): boolean {
  const permission = PAGE_PERMISSIONS[page]
  return !permission || can(subject, permission)
}
