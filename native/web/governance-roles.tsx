import { useId, useState } from "react"
import { Pencil, Plus, UserPlus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { TableCell, TableRow } from "@/components/ui/table"
import { Choice, Empty, RecordTable, Toolbar, contains, dateTime } from "./settings"
import { assignmentBody, groupRoleBody, permissionGroups, permissionLabel, roleBody, roleIdFromName, roleUsage, type RoleDraft } from "./governance-data"
import { DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, StatusBadge, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import {
  archiveGovernanceRole, assignGovernanceRole, createGovernanceRole, getPermissions, listGovernanceRoles, updateGovernanceGroupRole, updateGovernanceRole,
  type DirectoryGroup, type GovernanceGroupRole as GroupRole, type GovernanceRole as Role, type GovernanceRoleAssignment as RoleAssignment, type PermissionInfo, type RolesAdmin,
} from "./generated/api"

const NO_ROLE = "__none__"
const exceeds = (role: Role, grantable: readonly string[] | null) => grantable !== null && role.permissions.some(permission => !grantable.includes(permission))

export function RoleRows({ roles, catalog, assignments, groupRoles, grantable, onEdit, onArchive }: {
  roles: Role[]; catalog: readonly PermissionInfo[]; assignments: readonly RoleAssignment[]; groupRoles: readonly GroupRole[]
  grantable: readonly string[] | null; onEdit: (role: Role) => void; onArchive: (role: Role) => void
}) {
  return <div className="ns-records">{roles.map(role => {
    const usage = roleUsage(role, assignments, groupRoles), locked = exceeds(role, grantable)
    return <article className="ns-record" key={role.id}><div className="ns-record-copy">
      <div className="ns-record-title"><h3>{role.name}</h3><span className="ns-badge">{role.permissions.length === 1 ? "1 permission" : `${role.permissions.length} permissions`}</span>
        {role.archived && <StatusBadge tone="neutral">Archived</StatusBadge>}</div>
      {role.description && <p>{role.description}</p>}
      <details><summary>View permissions<span className="visually-hidden"> for {role.name}</span></summary>
        {role.permissions.length ? <ul className="ns-gov-permission-list">{role.permissions.map(id => <li key={id}><span>{permissionLabel(catalog, id)}</span><code>{id}</code></li>)}</ul>
          : <p className="ns-muted">No permissions. People assigned only this role cannot use Moyai.</p>}</details>
      <small>Role ID {role.id} · {usage.people === 1 ? "1 person" : `${usage.people} people`} · {usage.groups === 1 ? "1 group" : `${usage.groups} groups`} · Updated {dateTime(role.updated_at)}{role.updated_by ? ` by ${role.updated_by}` : ""}</small>
      {locked && !role.archived && <small>You can change this role only if you hold all of its permissions directly.</small>}
    </div>
      {!role.archived && !locked && <div className="ns-row-actions">
        <Button variant="outline" size="sm" onClick={() => onEdit(role)}><Pencil />Edit<span className="visually-hidden"> {role.name}</span></Button>
        <Button variant="ghost" size="sm" onClick={() => onArchive(role)}>Archive<span className="visually-hidden"> {role.name}</span></Button>
      </div>}
    </article>
  })}</div>
}

export function AssignmentRows({ rows, roles, onChange, onRemove }: { rows: RoleAssignment[]; roles: readonly Role[]; onChange: (row: RoleAssignment) => void; onRemove: (row: RoleAssignment) => void }) {
  return <RecordTable label="People with custom roles" headings={["Person", "Role", "Updated", "Actions"]}>{rows.map(row => {
    const role = roles.find(item => item.id === row.role_id)
    return <TableRow key={row.email}>
      <TableCell><strong>{row.email}</strong></TableCell>
      <TableCell>{row.role_name || role?.name || row.role_id}{role?.archived && <small>Archived role · no permissions until reassigned</small>}</TableCell>
      <TableCell>{dateTime(row.updated_at)}{row.updated_by && <small>By {row.updated_by}</small>}</TableCell>
      <TableCell><div className="ns-row-actions"><Button size="sm" variant="outline" onClick={() => onChange(row)}>Change<span className="visually-hidden"> role for {row.email}</span></Button>
        <Button size="sm" variant="ghost" onClick={() => onRemove(row)}>Remove<span className="visually-hidden"> custom role from {row.email}</span></Button></div></TableCell>
    </TableRow>
  })}</RecordTable>
}

export function GroupGrantRows({ groups, grants, roles, onChange }: { groups: DirectoryGroup[]; grants: readonly GroupRole[]; roles: readonly Role[]; onChange: (group: DirectoryGroup) => void }) {
  return <RecordTable label="Directory group grants" headings={["Group", "Members", "Additional role", "Actions"]}>{groups.map(group => {
    const grant = grants.find(row => row.group_id === group.id && row.role_id)
    const role = grant && roles.find(item => item.id === grant.role_id)
    return <TableRow key={group.id}>
      <TableCell><strong>{group.display_name}</strong></TableCell><TableCell>{group.member_count.toLocaleString()}</TableCell>
      <TableCell>{grant ? grant.role_name || role?.name || grant.role_id : "None"}{role?.archived && <small>Archived role · adds no permissions</small>}</TableCell>
      <TableCell><Button size="sm" variant="outline" onClick={() => onChange(group)}>Change grant<span className="visually-hidden"> for {group.display_name}</span></Button></TableCell>
    </TableRow>
  })}</RecordTable>
}

export function RolesPage() {
  const catalog = useGovResource("permissions", signal => getPermissions({ signal }).then(dataOf))
  const resource = useGovResource("roles", signal => listGovernanceRoles({ signal }).then(dataOf))
  const refresh = () => { catalog.refresh(); resource.refresh() }
  // Saves only refresh the listing: the server refuses changes to the signed-in person's own access, and a 403 re-reads it through useGovMutation.
  const both = { data: catalog.data && resource.data ? { catalog: catalog.data, admin: resource.data } : undefined, loading: catalog.loading || resource.loading,
    error: catalog.error || resource.error, status: catalog.error ? catalog.status : resource.status, refresh }
  const [search, setSearch] = useState(""), [state, setState] = useState("active"), [people, setPeople] = useState("")
  const [editor, setEditor] = useState<Role | "new" | null>(null), [archive, setArchive] = useState<Role | null>(null)
  const [assign, setAssign] = useState<RoleAssignment | "new" | null>(null), [remove, setRemove] = useState<RoleAssignment | null>(null)
  const [grant, setGrant] = useState<DirectoryGroup | null>(null)
  return <LoadGate resource={both} label="roles">{({ catalog: permissions, admin }) => {
    const rows = admin.roles.filter(role => (state === "all" || (state === "archived") === role.archived)
      && contains(search, role.name, role.description, role.id, ...role.permissions.map(id => permissionLabel(permissions.catalog, id))))
    const assigned = admin.assignments.filter(row => contains(people, row.email, row.role_name))
    const active = admin.roles.filter(role => !role.archived)
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Administrators hold every permission. Members hold the built-in Member set. A custom role replaces the Member set for each person assigned to it, and directory group grants add permissions on top.</p>
        <PageActions resource={both} /></div>
      <Section id="gov-roles" title="Custom roles" description="Define reusable permission sets. Changes apply on each person’s next request."
        action={<Button onClick={() => setEditor("new")}><Plus />New role</Button>}>
        <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search roles"
          filter={<Choice label="Role status" value={state} onChange={setState} options={[{ value: "active", label: "Active roles" }, { value: "archived", label: "Archived roles" }, { value: "all", label: "All roles" }]} />} />
        {rows.length ? <RoleRows roles={rows} catalog={permissions.catalog} assignments={admin.assignments} groupRoles={admin.group_roles} grantable={admin.grantable} onEdit={setEditor} onArchive={setArchive} />
          : admin.roles.length || search ? <Empty filtered noun="roles" onClear={() => { setSearch(""); setState("active") }} />
            : <div className="ns-empty"><h3>No custom roles yet</h3><p>Create a role to give people a narrower or broader permission set than Member.</p></div>}
        <details className="ns-gov-builtins"><summary>Built-in role permissions</summary>
          <dl><dt>Administrator</dt><dd>All {permissions.builtin_roles.admin.length} permissions, including governance and billing.</dd>
            <dt>Member</dt><dd>{permissions.builtin_roles.member.map(id => permissionLabel(permissions.catalog, id)).join(", ")}</dd></dl></details>
      </Section>
      <Section id="gov-assignments" title="People with custom roles" description="Assign a custom role by work email. Grant administrator access on the Users page."
        action={<Button variant="outline" disabled={!active.length} onClick={() => setAssign("new")}><UserPlus />Assign role</Button>}>
        {!active.length && <p className="ns-muted">Create a custom role before assigning one.</p>}
        {admin.assignments.length > 0 && <Toolbar search={people} setSearch={setPeople} count={assigned.length} label="Search people with custom roles" />}
        {assigned.length ? <AssignmentRows rows={assigned} roles={admin.roles} onChange={setAssign} onRemove={setRemove} />
          : admin.assignments.length ? <Empty filtered noun="people" onClear={() => setPeople("")} />
            : <p className="ns-muted">Nobody has a custom role. Everyone uses Administrator or Member.</p>}
      </Section>
      <Section id="gov-groups" title="Directory group grants" description="A group grant adds a role’s permissions to every active member of a provisioned group. It never grants administrator access.">
        {admin.groups.length ? <GroupGrantRows groups={admin.groups} grants={admin.group_roles} roles={admin.roles} onChange={setGrant} />
          : <p className="ns-muted">No directory groups yet. Groups appear after your identity provider provisions them; see <a className="ns-link" href="#settings/provisioning">Provisioning</a>.</p>}
      </Section>
      {editor && <RoleEditor role={editor === "new" ? undefined : editor} catalog={permissions.catalog} grantable={admin.grantable} onClose={() => setEditor(null)} onSaved={resource.refresh} onReload={refresh} />}
      {archive && <GovConfirm title={`Archive ${archive.name}?`} label="Archive role" onReload={refresh} onClose={() => setArchive(null)}
        description={<ArchiveEffect role={archive} admin={admin} />}
        onConfirm={async () => { await archiveGovernanceRole({ path: { identity: archive.id }, query: { revision: archive.revision } }); resource.refresh() }} />}
      {assign && <AssignmentEditor existing={assign === "new" ? undefined : assign} roles={active} onClose={() => setAssign(null)} onSaved={resource.refresh} onReload={refresh} />}
      {remove && <GovConfirm title={`Remove the custom role from ${remove.email}?`} label="Remove custom role" onReload={refresh} onClose={() => setRemove(null)}
        description="They return to the built-in Member permissions on their next request, plus any directory group grants. Administrator access is unchanged."
        onConfirm={async () => { await assignGovernanceRole({ body: assignmentBody(remove.email, "member", remove) }); resource.refresh() }} />}
      {grant && <GroupGrantEditor group={grant} existing={admin.group_roles.find(row => row.group_id === grant.id)} roles={active} onClose={() => setGrant(null)} onSaved={resource.refresh} onReload={refresh} />}
    </>
  }}</LoadGate>
}

function ArchiveEffect({ role, admin }: { role: Role; admin: RolesAdmin }) {
  const usage = roleUsage(role, admin.assignments, admin.group_roles)
  return <>{usage.people ? `${usage.people === 1 ? "1 person is" : `${usage.people} people are`} assigned this role directly. They lose all of its permissions immediately and have no workspace access until you assign another role. ` : "Nobody is assigned this role directly. "}
    {usage.groups ? `${usage.groups === 1 ? "1 directory group stops" : `${usage.groups} directory groups stop`} adding its permissions. ` : ""}Archived roles cannot be assigned or edited.</>
}

export function RoleEditor({ role, catalog, grantable, onClose, onSaved, onReload }: {
  role?: Role; catalog: readonly PermissionInfo[]; grantable: readonly string[] | null; onClose: () => void; onSaved: () => void; onReload: () => void
}) {
  const mutation = useGovMutation(), id = useId()
  const [draft, setDraft] = useState<RoleDraft>({ id: role?.id ?? "", name: role?.name ?? "", description: role?.description ?? "", permissions: role?.permissions ?? [] })
  const [idEdited, setIdEdited] = useState(Boolean(role))
  const toggle = (permission: string, checked: boolean) => setDraft(previous => ({ ...previous, permissions: checked ? [...new Set([...previous.permissions, permission])] : previous.permissions.filter(item => item !== permission) }))
  return <GovDialog wide title={role ? `Edit ${role.name}` : "New role"} busy={mutation.busy} onClose={onClose}
    description="Choose exactly what people with this role can do. It replaces the Member permission set for each person assigned to it.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); void mutation.run(async () => {
      if (role) await updateGovernanceRole({ path: { identity: role.id }, body: roleBody(draft, role, catalog) })
      else await createGovernanceRole({ body: roleBody(draft, undefined, catalog) })
    }, () => { onSaved(); onClose() }) }}>
      <div className="ns-gov-field-pair">
        <div className="ns-field"><label htmlFor={`${id}-name`}>Role name</label><Input id={`${id}-name`} autoFocus required minLength={2} maxLength={100} disabled={mutation.busy} value={draft.name}
          onChange={event => { const name = event.target.value; setDraft(previous => ({ ...previous, name, id: idEdited ? previous.id : roleIdFromName(name) })) }} /></div>
        <div className="ns-field"><label htmlFor={`${id}-id`}>Role ID</label><Input id={`${id}-id`} required maxLength={64} pattern="[a-z][a-z0-9]*(?:-[a-z0-9]+)*" disabled={mutation.busy || Boolean(role)} value={draft.id} aria-describedby={`${id}-id-hint`}
          onChange={event => { setIdEdited(true); setDraft(previous => ({ ...previous, id: event.target.value })) }} />
          <p id={`${id}-id-hint`} className="ns-field-hint">{role ? "Role IDs are permanent." : "Shown in the audit log. Lowercase letters, numbers and hyphens; it cannot be changed later."}</p></div>
      </div>
      <div className="ns-field"><label htmlFor={`${id}-description`}>Description (optional)</label><Textarea id={`${id}-description`} className="ns-gov-short" rows={2} maxLength={500} disabled={mutation.busy} value={draft.description} onChange={event => setDraft(previous => ({ ...previous, description: event.target.value }))} /></div>
      <fieldset className="ns-gov-permissions" aria-describedby={`${id}-permissions-hint`}><legend>Permissions</legend>
        <p id={`${id}-permissions-hint`} className="ns-field-hint">{draft.permissions.length} of {catalog.length} selected.{grantable ? " You can grant only permissions you hold directly; others are unavailable." : ""}</p>
        <div className="ns-gov-permission-groups">{permissionGroups(catalog).map(group => <fieldset key={group.group}><legend>{group.group}</legend>
          {group.items.map(item => {
            const locked = grantable !== null && !grantable.includes(item.id)
            return <div className="ns-gov-check" key={item.id}>
              <Checkbox id={`${id}-${item.id}`} checked={draft.permissions.includes(item.id)} disabled={mutation.busy || locked} aria-describedby={`${id}-${item.id}-description`}
                onCheckedChange={checked => toggle(item.id, checked === true)} />
              <div><label htmlFor={`${id}-${item.id}`}>{item.label}</label><small id={`${id}-${item.id}-description`}>{item.description} <code>{item.id}</code></small></div>
            </div>
          })}</fieldset>)}</div>
      </fieldset>
      {!draft.permissions.length && <p className="ns-notice" role="status">With no permissions, people assigned only this role cannot use Moyai.</p>}
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel={role ? "Save role" : "Create role"} />
    </form>
  </GovDialog>
}

export function AssignmentEditor({ existing, roles, onClose, onSaved, onReload }: { existing?: RoleAssignment; roles: readonly Role[]; onClose: () => void; onSaved: () => void; onReload: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [email, setEmail] = useState(existing?.email ?? "")
  const [roleId, setRoleId] = useState(existing && roles.some(role => role.id === existing.role_id) ? existing.role_id : roles[0]?.id ?? "")
  return <GovDialog title={existing ? `Change role for ${existing.email}` : "Assign a custom role"} busy={mutation.busy} onClose={onClose}
    description="The role replaces this person’s Member permissions on their next request. Directory group grants still add permissions.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); void mutation.run(async () => { await assignGovernanceRole({ body: assignmentBody(email, roleId, existing) }) }, () => { onSaved(); onClose() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-email`}>Work email</label><Input id={`${id}-email`} type="email" autoFocus={!existing} required maxLength={254} autoComplete="off" disabled={mutation.busy || Boolean(existing)} value={email} onChange={event => setEmail(event.target.value)} /></div>
      <div className="ns-field"><label htmlFor={`${id}-role`}>Role</label><Choice id={`${id}-role`} label="Role" value={roleId} disabled={mutation.busy} onChange={setRoleId} options={roles.map(role => ({ value: role.id, label: role.name }))} /></div>
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel="Assign role" disabled={!roleId} />
    </form>
  </GovDialog>
}

export function GroupGrantEditor({ group, existing, roles, onClose, onSaved, onReload }: { group: DirectoryGroup; existing?: GroupRole; roles: readonly Role[]; onClose: () => void; onSaved: () => void; onReload: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [roleId, setRoleId] = useState(existing?.role_id && roles.some(role => role.id === existing.role_id) ? existing.role_id : NO_ROLE)
  return <GovDialog title={`Grant for ${group.display_name}`} busy={mutation.busy} onClose={onClose}
    description={`Each of the ${group.member_count.toLocaleString()} active members gains this role’s permissions in addition to their own role.`}>
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); void mutation.run(async () => { await updateGovernanceGroupRole({ path: { identity: group.id }, body: groupRoleBody(roleId === NO_ROLE ? "" : roleId, existing) }) }, () => { onSaved(); onClose() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-role`}>Additional role</label><Choice id={`${id}-role`} label="Additional role" value={roleId} disabled={mutation.busy} onChange={setRoleId}
        options={[{ value: NO_ROLE, label: "No additional role" }, ...roles.map(role => ({ value: role.id, label: role.name }))]} />
        <p className="ns-field-hint">Removing a grant takes effect on each member’s next request.</p></div>
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel="Save grant" />
    </form>
  </GovDialog>
}
