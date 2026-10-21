import { useEffect, useId, useRef, useState } from "react"
import { KeyRound, Plus, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { TableCell, TableRow } from "@/components/ui/table"
import { csrfToken } from "./api"
import { Choice, Empty, RecordTable, Toolbar, contains, dateTime, errorText } from "./settings"
import { ActivityList, CopyField, DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, StatusBadge, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import {
  createScimToken, getScimAdmin, revokeScimToken,
  type CreatedScimToken, type ScimAdmin, type ScimGroupSummary as ScimGroup, type ScimToken, type ScimUserSummary as ScimUser,
} from "./generated/api"

const PAGE_SIZE = 50

export function TokenRows({ tokens, onRevoke }: { tokens: ScimToken[]; onRevoke?: (token: ScimToken) => void }) {
  return <RecordTable label="Provisioning tokens" headings={["Token", "Created", "Last used", "Status", "Actions"]}>{tokens.map(token => <TableRow key={token.id}>
    <TableCell><strong>{token.label}</strong><small><code>{token.prefix}…</code></small></TableCell>
    <TableCell>{dateTime(token.created_at)}{token.created_by && <small>By {token.created_by}</small>}</TableCell>
    <TableCell>{token.last_used_at ? dateTime(token.last_used_at) : "Never used"}</TableCell>
    <TableCell>{token.revoked_at ? <><StatusBadge tone="neutral">Revoked</StatusBadge><small>{dateTime(token.revoked_at)}</small></> : <StatusBadge tone="success">Active</StatusBadge>}</TableCell>
    <TableCell><div className="ns-row-actions">{!token.revoked_at && onRevoke && <Button size="sm" variant="ghost" onClick={() => onRevoke(token)}>Revoke<span className="visually-hidden"> {token.label}</span></Button>}</div></TableCell>
  </TableRow>)}</RecordTable>
}

export function DirectoryUserRows({ users }: { users: ScimUser[] }) {
  return <RecordTable label="Directory users" headings={["Person", "Status", "Groups", "External ID", "Updated"]}>{users.map(user => <TableRow key={user.id}>
    <TableCell><strong>{user.display_name || user.user_name}</strong><small>{user.user_name}</small></TableCell>
    <TableCell>{user.active ? <StatusBadge tone="success">Active</StatusBadge> : <StatusBadge tone="danger">Deactivated</StatusBadge>}</TableCell>
    <TableCell>{user.groups_count.toLocaleString()}</TableCell>
    <TableCell>{user.external_id ? <code>{user.external_id}</code> : <span className="ns-muted">None</span>}</TableCell>
    <TableCell>{dateTime(user.updated_at)}</TableCell>
  </TableRow>)}</RecordTable>
}

export function DirectoryGroupRows({ groups }: { groups: ScimGroup[] }) {
  return <RecordTable label="Directory groups" headings={["Group", "Members", "Additional role"]}>{groups.map(group => <TableRow key={group.id}>
    <TableCell><strong>{group.display_name}</strong></TableCell><TableCell>{group.member_count.toLocaleString()}</TableCell>
    <TableCell>{group.role_id ? group.role_name || group.role_id : "None"}</TableCell>
  </TableRow>)}</RecordTable>
}

export function ProvisioningPage({ canManageRoles }: { canManageRoles: boolean }) {
  const resource = useGovResource("scim", signal => getScimAdmin({ query: { limit: PAGE_SIZE }, signal }).then(dataOf))
  const [pages, setPages] = useState<{ base?: ScimAdmin; items: ScimUser[]; next: string | null; loaded: boolean; loading: boolean; error: string }>({ items: [], next: null, loaded: false, loading: false, error: "" })
  const loadMore = useRef<AbortController | null>(null)
  const [search, setSearch] = useState(""), [status, setStatus] = useState("all")
  const [create, setCreate] = useState(false), [revoke, setRevoke] = useState<ScimToken | null>(null)
  // A refresh replaces earlier pages; a late page from before it is ignored.
  useEffect(() => { loadMore.current?.abort(); setPages({ base: resource.data, items: [], next: null, loaded: false, loading: false, error: "" }) }, [resource.data])
  useEffect(() => () => loadMore.current?.abort(), [])
  return <><LoadGate resource={resource} label="provisioning">{data => {
    const next = pages.base === data && pages.loaded ? pages.next : data.users.next_cursor
    const users = [...new Map([...data.users.items, ...(pages.base === data ? pages.items : [])].map(user => [user.id, user])).values()]
    const rows = users.filter(user => contains(search, user.user_name, user.display_name, user.external_id) && (status === "all" || (status === "active") === user.active))
    const more = () => {
      if (!next || pages.loading) return
      const controller = new AbortController(), auth = csrfToken()
      loadMore.current?.abort(); loadMore.current = controller
      setPages(previous => ({ ...previous, loading: true, error: "" }))
      void getScimAdmin({ query: { limit: PAGE_SIZE, cursor: next }, signal: controller.signal }).then(({ data: page }) => {
        if (controller.signal.aborted || auth !== csrfToken()) return
        setPages(previous => previous.base === data ? { base: data, items: [...previous.items, ...page.users.items], next: page.users.next_cursor, loaded: true, loading: false, error: "" } : previous)
      }, reason => { if (!controller.signal.aborted) setPages(previous => ({ ...previous, loading: false, error: errorText(reason) })) })
    }
    // The first page (no cursor) carries the sections; load-more pages only add users.
    const tokens = data.tokens ?? [], groups = data.groups ?? [], activity = data.activity ?? []
    const active = tokens.filter(token => !token.revoked_at).length
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Your identity provider creates, updates and deactivates people and groups through SCIM 2.0. Deactivated people lose access immediately, and their queued or running work is stopped.</p>
        <PageActions resource={resource} /></div>
      <Section id="gov-scim" title="SCIM connection" description="Enter this URL and a provisioning token in your identity provider, for example Okta or Microsoft Entra ID.">
        <CopyField id="gov-scim-url" label="SCIM base URL" value={data.base_url} hint="If Cloudflare Access protects Moyai, add a bypass policy for this path so your identity provider can reach it." />
      </Section>
      <Section id="gov-tokens" title="Provisioning tokens" description={`${active === 1 ? "1 active token" : `${active} active tokens`}. Tokens are stored as hashes and are shown only when created.`}
        action={data.can_create_tokens && <Button onClick={() => setCreate(true)}><Plus />Create token</Button>}>
        {!data.can_create_tokens && <p className="ns-muted">A built-in administrator creates provisioning tokens. You can review and revoke them.</p>}
        {tokens.length ? <TokenRows tokens={tokens} onRevoke={setRevoke} /> : <p className="ns-muted">No provisioning tokens yet.{data.can_create_tokens ? " Create one to connect your identity provider." : ""}</p>}
      </Section>
      <Section id="gov-directory-users" title="Directory users" description="People provisioned by your identity provider. Their role is managed under Users and Roles & access.">
        <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search directory users"
          filter={<Choice label="Directory status" value={status} onChange={setStatus} options={[{ value: "all", label: "All statuses" }, { value: "active", label: "Active" }, { value: "inactive", label: "Deactivated" }]} />} />
        {next && (search || status !== "all") && <p className="ns-muted">Search and status filter the loaded users. Load more to include the rest of the directory.</p>}
        {rows.length ? <DirectoryUserRows users={rows} /> : users.length ? <Empty filtered noun="directory users" onClear={() => { setSearch(""); setStatus("all") }} />
          : <p className="ns-muted">No people have been provisioned yet.</p>}
        {pages.error && <p className="ns-error" role="alert">{pages.error}</p>}
        {next && <Button className="ns-gov-more" variant="outline" disabled={pages.loading} onClick={more}>{pages.loading ? "Loading users…" : "Load more users"}</Button>}
      </Section>
      <Section id="gov-directory-groups" title="Directory groups" description={canManageRoles ? <>Grant a role to a group in <a className="ns-link" href="#settings/roles">Roles & access</a>.</> : "Group role grants are managed by people with the roles.manage permission."}>
        {groups.length ? <DirectoryGroupRows groups={groups} /> : <p className="ns-muted">No groups have been provisioned yet.</p>}
      </Section>
      <Section id="gov-scim-activity" title="Recent provisioning activity">
        <ActivityList entries={activity} empty="Provisioning changes appear here after your identity provider syncs." />
      </Section>
      {revoke && <GovConfirm title={`Revoke ${revoke.label}?`} label="Revoke token" onReload={resource.refresh} onClose={() => setRevoke(null)}
        description="Your identity provider can no longer sync with this token. People and groups already provisioned are kept. This cannot be undone; create a new token to reconnect."
        onConfirm={async () => { await revokeScimToken({ path: { identity: revoke.id } }); resource.refresh() }} />}
    </>
  }}</LoadGate>
    {/* Outside the load gate: a failed list refresh must not discard the one-time token. */}
    {create && <TokenDialog onClose={() => setCreate(false)} onCreated={resource.refresh} />}
  </>
}

/** The secret exists only in this dialog's state and is dropped when it closes. */
export function TokenDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [label, setLabel] = useState("")
  const [created, setCreated] = useState<CreatedScimToken | null>(null)
  const done = () => { setCreated(null); onClose() }
  if (created) return <GovDialog title="Copy your provisioning token" dismissible={false} onClose={done}
    description="Paste it into your identity provider’s SCIM settings now.">
    <p className="ns-gov-warning" role="alert"><TriangleAlert size={16} aria-hidden="true" /><span><strong>This token is shown only once.</strong> Moyai stores only a hash. If you lose it, revoke it and create another.</span></p>
    <CopyField id={`${id}-token`} label={`Bearer token for ${created.label}`} value={created.token} secret autoFocus />
    <div className="ns-dialog-actions"><Button type="button" onClick={done}>Done</Button></div>
  </GovDialog>
  return <GovDialog title="Create provisioning token" busy={mutation.busy} onClose={onClose}
    description="Create one token per identity provider so you can revoke it independently.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); let result: CreatedScimToken; void mutation.run(async () => {
      const value = label.trim()
      if (!value || value.length > 80) throw new Error("Use a label between 1 and 80 characters.")
      const { data } = await createScimToken({ body: { label: value } })
      // The secret is returned only here; never open the one-time view without it.
      if (!data.token) throw new Error("The server did not return the new token. Revoke it and try again.")
      result = data
    }, () => { setCreated(result); onCreated() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-label`}><KeyRound size={14} aria-hidden="true" /> Token label</label><Input id={`${id}-label`} autoFocus required maxLength={80} autoComplete="off" placeholder="Okta production" disabled={mutation.busy} value={label} onChange={event => setLabel(event.target.value)} />
        <p className="ns-field-hint">Shown in the token list and audit log.</p></div>
      <MutationError mutation={mutation} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel="Create token" busyLabel="Creating…" />
    </form>
  </GovDialog>
}
