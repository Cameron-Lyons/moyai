import { useId, useState } from "react"
import { KeyRound, Pencil, Plus, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { TableCell, TableRow } from "@/components/ui/table"
import { Choice, Empty, RecordTable, Toolbar, contains, dateTime } from "./settings"
import {
  DEFAULT_EXPIRY, EXPIRY_CHOICES, activeKeys, canIssueKey, collectorCommand, keyState, permissionLabel, serviceAccountBody, serviceAccountState, serviceKeyBody,
  type ServiceAccountDraft,
} from "./governance-data"
import { ActivityList, CopyField, DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, StatusBadge, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import {
  createServiceAccount, createServiceAccountKey, disableServiceAccount, getPermissions, listServiceAccounts, revokeServiceAccountKey, updateServiceAccount,
  type CreatedServiceAccountKey, type PermissionInfo, type ServiceAccountKey, type ServiceAccountView as ServiceAccount,
} from "./generated/api"

const DISABLED_BY_ACCOUNT = "service_account.disabled"
const disableEffect = (keys: number) => `${keys === 0 ? "It has no unrevoked keys." : keys === 1
  ? "Its key is revoked permanently, and collectors using it stop on their next request, including downloads in progress."
  : `All ${keys} of its keys are revoked permanently, and collectors using them stop on their next request, including downloads in progress.`} Enabling the account later does not restore revoked keys.`

export function KeyRows({ keys, onRevoke, now }: { keys: ServiceAccountKey[]; onRevoke?: (key: ServiceAccountKey) => void; now?: number }) {
  return <RecordTable label="API keys" headings={["Key", "Created", "Expires", "Last used", "Status", "Actions"]}>{keys.map(key => {
    const state = keyState(key, now)
    return <TableRow key={key.id}>
      <TableCell><strong>{key.label}</strong><small><code>{key.prefix}…</code></small></TableCell>
      <TableCell>{dateTime(key.created_at)}{key.created_by && <small>By {key.created_by}</small>}</TableCell>
      <TableCell>{dateTime(key.expires_at)}{state.note && <small>{state.note}</small>}</TableCell>
      <TableCell>{key.last_used_at ? <>{dateTime(key.last_used_at)}{key.last_used_from && <small>From <code>{key.last_used_from}</code></small>}</> : "Never used"}</TableCell>
      <TableCell><StatusBadge tone={state.tone}>{state.label}</StatusBadge>
        {key.revoked_at && <small>{dateTime(key.revoked_at)}{key.revoked_by === DISABLED_BY_ACCOUNT ? " · account disabled" : key.revoked_by ? ` · by ${key.revoked_by}` : ""}</small>}</TableCell>
      <TableCell><div className="ns-row-actions">{!key.revoked_at && onRevoke && <Button size="sm" variant="ghost" onClick={() => onRevoke(key)}>Revoke<span className="visually-hidden"> {key.label}</span></Button>}</div></TableCell>
    </TableRow>
  })}</RecordTable>
}

function AccountRecord({ account, catalog, canCreate, maxActiveKeys, onEdit, onIssue, onDisable, onEnable, onRevoke }: {
  account: ServiceAccount; catalog: readonly PermissionInfo[]; canCreate: boolean; maxActiveKeys: number
  onEdit: () => void; onIssue: () => void; onDisable: () => void; onEnable: () => void; onRevoke: (key: ServiceAccountKey) => void
}) {
  const usable = activeKeys(account), issuable = canIssueKey(account, maxActiveKeys)
  return <article className="ns-record">
    <div className="ns-record-copy">
      <div className="ns-record-title"><h3>{account.name}</h3>
        {account.active ? <StatusBadge tone="success">Active</StatusBadge> : <StatusBadge tone="neutral">Disabled</StatusBadge>}
        {account.permissions.map(id => <span className="ns-badge" key={id} title={id}>{permissionLabel(catalog, id)}</span>)}</div>
      {account.description && <p>{account.description}</p>}
      <small>{usable === 1 ? "1 active key" : `${usable} active keys`} · Created {dateTime(account.created_at)}{account.created_by ? ` by ${account.created_by}` : ""}
        {account.updated_at !== account.created_at ? ` · Updated ${dateTime(account.updated_at)}${account.updated_by ? ` by ${account.updated_by}` : ""}` : ""}</small>
    </div>
    <div className="ns-row-actions">
      {canCreate && account.active && <Button size="sm" disabled={!issuable} onClick={onIssue}><KeyRound />New key<span className="visually-hidden"> for {account.name}</span></Button>}
      {canCreate && <Button size="sm" variant="outline" onClick={onEdit}><Pencil />Edit<span className="visually-hidden"> {account.name}</span></Button>}
      {account.active ? <Button size="sm" variant="ghost" onClick={onDisable}>Disable<span className="visually-hidden"> {account.name}</span></Button>
        : canCreate && <Button size="sm" variant="ghost" onClick={onEnable}>Enable<span className="visually-hidden"> {account.name}</span></Button>}
    </div>
    <div className="ns-gov-account-keys">
      {canCreate && account.active && !issuable && <p className="ns-muted">This account has the maximum of {maxActiveKeys} active keys. Revoke one to issue another.</p>}
      {account.keys.length ? <KeyRows keys={account.keys} onRevoke={onRevoke} />
        : <p className="ns-muted">No keys yet.{canCreate && account.active ? " Issue one for your collector." : ""}</p>}
    </div>
  </article>
}

export function ServiceAccountsPage() {
  const catalog = useGovResource("permissions", signal => getPermissions({ signal }).then(dataOf))
  const resource = useGovResource("service-accounts", signal => listServiceAccounts({ signal }).then(dataOf))
  const refresh = () => { catalog.refresh(); resource.refresh() }
  const both = { data: catalog.data && resource.data ? { catalog: catalog.data.catalog, admin: resource.data } : undefined, loading: catalog.loading || resource.loading,
    error: catalog.error || resource.error, status: catalog.error ? catalog.status : resource.status, refresh }
  const [search, setSearch] = useState(""), [state, setState] = useState("active")
  const [editor, setEditor] = useState<ServiceAccount | "new" | null>(null), [issue, setIssue] = useState<ServiceAccount | null>(null)
  const [disable, setDisable] = useState<ServiceAccount | null>(null), [enable, setEnable] = useState<ServiceAccount | null>(null)
  const [revoke, setRevoke] = useState<{ account: ServiceAccount; key: ServiceAccountKey } | null>(null)
  return <><LoadGate resource={both} label="service accounts">{({ catalog: permissions, admin }) => {
    const rows = admin.accounts.filter(account => (state === "all" || (state === "active") === account.active)
      && contains(search, account.name, account.description, ...account.keys.flatMap(key => [key.label, key.prefix])))
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Service accounts let tools such as a SIEM collector read the audit log and organization spend without a person signing in. Their API keys are read-only, expire, work only on the endpoints listed below and can be revoked at any time.</p>
        <PageActions resource={both} /></div>
      <Section id="gov-service-accounts" title="Service accounts" description="Each account holds only the permissions chosen for it, and only from the read permissions keys may use."
        action={admin.can_create && <Button onClick={() => setEditor("new")}><Plus />New service account</Button>}>
        {!admin.can_create && <p className="ns-muted">A built-in administrator creates service accounts, changes their permissions and issues keys. You can review them, revoke keys and disable accounts.</p>}
        {admin.accounts.length > 0 && <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search service accounts"
          filter={<Choice label="Account status" value={state} onChange={setState} options={[{ value: "active", label: "Active accounts" }, { value: "disabled", label: "Disabled accounts" }, { value: "all", label: "All accounts" }]} />} />}
        {rows.length ? <div className="ns-records">{rows.map(account => <AccountRecord key={account.id} account={account} catalog={permissions} canCreate={admin.can_create} maxActiveKeys={admin.max_active_keys}
          onEdit={() => setEditor(account)} onIssue={() => setIssue(account)} onDisable={() => setDisable(account)} onEnable={() => setEnable(account)}
          onRevoke={key => setRevoke({ account, key })} />)}</div>
          : admin.accounts.length ? <Empty filtered noun="service accounts" onClear={() => { setSearch(""); setState("active") }} />
            : <div className="ns-empty"><h3>No service accounts yet</h3><p>{admin.can_create ? "Create one for each tool that reads Moyai, so you can revoke it independently." : "None have been created."}</p></div>}
      </Section>
      <Section id="gov-key-routes" title="Endpoints that accept API keys" description="Keys are refused everywhere else, including every change, so a key can never manage keys or act as a person.">
        <ul className="ns-gov-permission-list">{admin.key_routes.map(route => <li key={`${route.method} ${route.path}`}>
          <span><code>{route.method} {route.path}</code></span><span>{permissionLabel(permissions, route.permission)}</span></li>)}</ul>
        <CopyField id="gov-collector-command" mono label="Example audit export request" value={collectorCommand(window.location.origin)}
          hint="Set MOYAI_API_KEY to the key. Poll with after and before (ISO-8601) and deduplicate NDJSON lines on source and id. If Cloudflare Access protects Moyai, also send your Access service token headers." />
      </Section>
      <Section id="gov-service-activity" title="Recent service account activity">
        <ActivityList entries={admin.activity} empty="Service account and key changes appear here." />
      </Section>
      {editor && <AccountEditor account={editor === "new" ? undefined : editor} ceiling={admin.permission_ceiling} catalog={permissions}
        onClose={() => setEditor(null)} onSaved={resource.refresh} onReload={refresh} />}
      {disable && <GovConfirm title={`Disable ${disable.name}?`} label="Disable account" onReload={refresh} onClose={() => setDisable(null)}
        description={disableEffect(disable.keys.filter(key => !key.revoked_at).length)}
        onConfirm={async () => { await disableServiceAccount({ path: { identity: disable.id }, query: { revision: disable.revision } }); resource.refresh() }} />}
      {enable && <GovConfirm title={`Enable ${enable.name}?`} label="Enable account" busyLabel="Enabling…" destructive={false} onReload={refresh} onClose={() => setEnable(null)}
        description="The account can receive new keys again. Keys revoked when it was disabled stay revoked."
        onConfirm={async () => { await updateServiceAccount({ path: { identity: enable.id }, body: serviceAccountState(enable, true) }); resource.refresh() }} />}
      {revoke && <GovConfirm title={`Revoke ${revoke.key.label}?`} label="Revoke key" onReload={refresh} onClose={() => setRevoke(null)}
        description={`Collectors using ${revoke.key.prefix}… stop on their next request, including downloads in progress. This cannot be undone; issue a new key to reconnect.`}
        onConfirm={async () => { await revokeServiceAccountKey({ path: { identity: revoke.account.id, key_id: revoke.key.id } }); resource.refresh() }} />}
    </>
  }}</LoadGate>
    {/* Outside the load gate: a failed list refresh must not discard the one-time key. */}
    {issue && <KeyDialog account={issue} onClose={() => setIssue(null)} onCreated={resource.refresh} />}
  </>
}

function AccountEditor({ account, ceiling, catalog, onClose, onSaved, onReload }: {
  account?: ServiceAccount; ceiling: readonly string[]; catalog: readonly PermissionInfo[]; onClose: () => void; onSaved: () => void; onReload: () => void
}) {
  const mutation = useGovMutation(), id = useId()
  const [draft, setDraft] = useState<ServiceAccountDraft>({ name: account?.name ?? "", description: account?.description ?? "", permissions: account?.permissions ?? [] })
  const toggle = (permission: string, checked: boolean) => setDraft(previous => ({ ...previous, permissions: checked ? [...new Set([...previous.permissions, permission])] : previous.permissions.filter(item => item !== permission) }))
  const narrowed = account && account.permissions.some(permission => !draft.permissions.includes(permission))
  return <GovDialog title={account ? `Edit ${account.name}` : "New service account"} busy={mutation.busy} onClose={onClose}
    description="Choose what this account's keys may read. Permission changes apply to existing keys on their next request.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); void mutation.run(async () => {
      if (account) await updateServiceAccount({ path: { identity: account.id }, body: serviceAccountBody(draft, account, ceiling) })
      else await createServiceAccount({ body: serviceAccountBody(draft, undefined, ceiling) })
    }, () => { onSaved(); onClose() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-name`}>Name</label><Input id={`${id}-name`} autoFocus required minLength={2} maxLength={80} autoComplete="off" placeholder="SIEM collector" disabled={mutation.busy} value={draft.name}
        onChange={event => { const name = event.target.value; setDraft(previous => ({ ...previous, name })) }} /></div>
      <div className="ns-field"><label htmlFor={`${id}-description`}>Description (optional)</label><Textarea id={`${id}-description`} className="ns-gov-short" rows={2} maxLength={500} disabled={mutation.busy} value={draft.description}
        onChange={event => { const description = event.target.value; setDraft(previous => ({ ...previous, description })) }} /></div>
      <fieldset className="ns-gov-permissions" aria-describedby={`${id}-permissions-hint`}><legend>Permissions</legend>
        <p id={`${id}-permissions-hint`} className="ns-field-hint">Service accounts can hold only these read permissions.</p>
        {ceiling.map(permission => {
          const item = catalog.find(entry => entry.id === permission)
          return <div className="ns-gov-check" key={permission}>
            <Checkbox id={`${id}-${permission}`} checked={draft.permissions.includes(permission)} disabled={mutation.busy} aria-describedby={`${id}-${permission}-description`}
              onCheckedChange={checked => toggle(permission, checked === true)} />
            <div><label htmlFor={`${id}-${permission}`}>{item?.label ?? permission}</label><small id={`${id}-${permission}-description`}>{item?.description} <code>{permission}</code></small></div>
          </div>
        })}
      </fieldset>
      {narrowed && <p className="ns-notice" role="status">Keys lose the removed permissions on their next request. Downloads in progress stop.</p>}
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel={account ? "Save account" : "Create account"} />
    </form>
  </GovDialog>
}

/** The key exists only in this dialog's state and is dropped when it closes. */
export function KeyDialog({ account, onClose, onCreated }: { account: ServiceAccount; onClose: () => void; onCreated: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [label, setLabel] = useState(""), [days, setDays] = useState(String(DEFAULT_EXPIRY))
  const [created, setCreated] = useState<CreatedServiceAccountKey | null>(null)
  const done = () => { setCreated(null); onClose() }
  if (created) return <GovDialog title="Copy your API key" dismissible={false} onClose={done}
    description={`Store it in ${account.name}'s secret configuration now. It expires on ${dateTime(created.expires_at)}.`}>
    <p className="ns-gov-warning" role="alert"><TriangleAlert size={16} aria-hidden="true" /><span><strong>This key is shown only once.</strong> Moyai stores only a hash. If you lose it, revoke it and issue another.</span></p>
    <CopyField id={`${id}-key`} label={`API key ${created.label}`} value={created.token} secret autoFocus />
    <div className="ns-dialog-actions"><Button type="button" onClick={done}>Done</Button></div>
  </GovDialog>
  return <GovDialog title={`New key for ${account.name}`} busy={mutation.busy} onClose={onClose}
    description="Issue one key per collector so you can revoke it independently. Every key expires.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); let result: CreatedServiceAccountKey; void mutation.run(async () => {
      const { data } = await createServiceAccountKey({ path: { identity: account.id }, body: serviceKeyBody(label, Number(days)) })
      // The key is returned only here; never open the one-time view without it.
      if (!data.token) throw new Error("The server did not return the new key. Revoke it and try again.")
      result = data
    }, () => { setCreated(result); onCreated() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-label`}><KeyRound size={14} aria-hidden="true" /> Key label</label><Input id={`${id}-label`} autoFocus required maxLength={80} autoComplete="off" placeholder="Splunk production" disabled={mutation.busy} value={label} onChange={event => setLabel(event.target.value)} />
        <p className="ns-field-hint">Shown in the key list and audit log.</p></div>
      <div className="ns-field"><label htmlFor={`${id}-expiry`}>Expires after</label><Choice id={`${id}-expiry`} label="Expires after" value={days} disabled={mutation.busy} onChange={setDays}
        options={EXPIRY_CHOICES.map(choice => ({ value: String(choice), label: `${choice} days` }))} />
        <p className="ns-field-hint">Issue a replacement before it expires; expired keys stop working.</p></div>
      <MutationError mutation={mutation} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel="Issue key" busyLabel="Issuing…" />
    </form>
  </GovDialog>
}
