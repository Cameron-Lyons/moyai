import { useId, useState } from "react"
import { Plus, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { TableCell, TableRow } from "@/components/ui/table"
import { Choice, Empty, RecordTable, Toolbar, contains, dateTime } from "./settings"
import { limitSourceText, limitText, normalizeEmail, overrideChange, parseUsd, spendChanges, tierChange, usd, usdInput } from "./governance-data"
import { DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import { deleteSpendLimit, getEffectiveSpendLimit, getSpendLimits, updateSpendLimits, type DirectoryGroup, type EffectiveSpendLimit, type SpendGroupLimitView as SpendTier, type SpendLimitView as SpendLimit, type SpendLimitsAdmin, type SpendOrphanedGroupLimitView as DeletedTier } from "./generated/api"

const singletons = [
  { id: "organization", label: "Organization monthly limit", hint: "Total model spend for everyone this calendar month (UTC)." },
  { id: "user-default", label: "Default monthly limit per person", hint: "Applies to each person without an override or a directory group tier below." },
  { id: "session-default", label: "Limit per session", hint: "Lifetime model spend for a session and all its delegated agents." },
] as const
const monthStart = (value: string) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" }) : "the start of this month"
const requests = (count: number) => count === 1 ? "1 model request" : `${count} model requests`
const members = (count: number) => count === 1 ? "1 active member" : `${count.toLocaleString()} active members`
const deletedGroup = (row: DeletedTier) => row.group_name || "Unknown group"

/** Usage is null for a viewer without spend.read; the summary is then omitted. */
export function SpendSummary({ data }: { data: SpendLimitsAdmin }) {
  const usage = data.usage
  if (!usage) return null
  const organization = data.limits.find(limit => limit.id === "organization")
  const used = usage.organization_month_usd, limit = organization?.limit_usd ?? null
  const remaining = limit === null ? null : Math.max(0, limit - used)
  return <>
    {usage.unknown_requests > 0 && <p className="ns-notice" role="status">{requests(usage.unknown_requests)} finished without a reported cost. Reported spend is incomplete; configured limits block further requests until their costs are recovered.</p>}
    {usage.unresolved_requests > 0 && <p className="ns-notice" role="status">The cost of {requests(usage.unresolved_requests)} could not be recovered and is excluded from reported spend and limits. Review it against the gateway's spend logs.</p>}
    <dl className="ns-gov-stats" aria-label="Organization spend this month">
      <div><dt>Spent since {monthStart(usage.period_start)}</dt><dd>{usd(used)}{usage.in_flight_requests > 0 && <small>Excludes {requests(usage.in_flight_requests)} still running.</small>}</dd></div>
      <div><dt>Organization limit</dt><dd>{limitText(limit)}</dd></div>
      <div><dt>Remaining this month</dt><dd>{limit !== null && usage.unknown_requests > 0 ? "Pending cost reconciliation" : remaining === null ? "No limit" : usd(remaining)}{limit !== null && used >= limit && <small>Limit reached. New model requests are refused.</small>}</dd></div>
    </dl>
  </>
}

export function OverrideRows({ rows, canManage, onEdit, onRemove }: { rows: SpendLimit[]; canManage: boolean; onEdit: (row: SpendLimit) => void; onRemove: (row: SpendLimit) => void }) {
  return <RecordTable label="Per-person spend overrides" headings={["Person", "Monthly limit", "Spent this month", "Updated", ...canManage ? ["Actions"] : []]}>{rows.map(row => <TableRow key={row.id}>
    <TableCell><strong>{row.subject}</strong></TableCell><TableCell>{limitText(row.limit_usd)}</TableCell>
    <TableCell>{usd(row.used_usd)}{row.limit_usd !== null && (row.used_usd ?? 0) >= row.limit_usd && <small>Limit reached</small>}</TableCell>
    <TableCell>{dateTime(row.updated_at)}{row.updated_by && <small>By {row.updated_by}</small>}</TableCell>
    {canManage && <TableCell><div className="ns-row-actions"><Button size="sm" variant="outline" onClick={() => onEdit(row)}>Edit<span className="visually-hidden"> limit for {row.subject}</span></Button>
      <Button size="sm" variant="ghost" onClick={() => onRemove(row)}>Remove<span className="visually-hidden"> override for {row.subject}</span></Button></div></TableCell>}
  </TableRow>)}</RecordTable>
}

export function TierRows({ rows, canManage, onEdit, onRemove }: { rows: SpendTier[]; canManage: boolean; onEdit: (row: SpendTier) => void; onRemove: (row: SpendTier) => void }) {
  return <RecordTable label="Directory group spend tiers" headings={["Group", "Active members", "Monthly limit per person", "Updated", ...canManage ? ["Actions"] : []]}>{rows.map(row => <TableRow key={row.id}>
    <TableCell><strong>{row.group_name}</strong></TableCell><TableCell>{row.member_count.toLocaleString()}</TableCell>
    <TableCell>{limitText(row.limit_usd)}{row.limit_usd === null && <small>Members are exempt from the default</small>}</TableCell>
    <TableCell>{dateTime(row.updated_at)}{row.updated_by && <small>By {row.updated_by}</small>}</TableCell>
    {canManage && <TableCell><div className="ns-row-actions"><Button size="sm" variant="outline" onClick={() => onEdit(row)}>Edit<span className="visually-hidden"> tier for {row.group_name}</span></Button>
      <Button size="sm" variant="ghost" onClick={() => onRemove(row)}>Remove<span className="visually-hidden"> tier for {row.group_name}</span></Button></div></TableCell>}
  </TableRow>)}</RecordTable>
}

/** Tiers of deleted directory groups apply to no one, but count toward tier capacity until removed. */
export function DeletedTierRows({ rows, canManage, onRemove }: { rows: DeletedTier[]; canManage: boolean; onRemove: (row: DeletedTier) => void }) {
  return <RecordTable label="Tiers of deleted directory groups" headings={["Deleted group", "Monthly limit per person", "Updated", ...canManage ? ["Actions"] : []]}>{rows.map(row => <TableRow key={row.id}>
    <TableCell><strong>{deletedGroup(row)}</strong></TableCell><TableCell>{limitText(row.limit_usd)}</TableCell>
    <TableCell>{dateTime(row.updated_at)}{row.updated_by && <small>By {row.updated_by}</small>}</TableCell>
    {canManage && <TableCell><div className="ns-row-actions"><Button size="sm" variant="ghost" onClick={() => onRemove(row)}>Remove<span className="visually-hidden"> tier for deleted group {deletedGroup(row)}</span></Button></div></TableCell>}
  </TableRow>)}</RecordTable>
}

export function SpendLimitsPage({ canManage }: { canManage: boolean }) {
  const resource = useGovResource("spend-limits", signal => getSpendLimits({ signal }).then(dataOf))
  const [search, setSearch] = useState("")
  const [editor, setEditor] = useState<SpendLimit | "new" | null>(null), [remove, setRemove] = useState<SpendLimit | null>(null)
  const [tierEditor, setTierEditor] = useState<SpendTier | "new" | null>(null), [removeTier, setRemoveTier] = useState<SpendTier | null>(null)
  const [removeDeleted, setRemoveDeleted] = useState<DeletedTier | null>(null)
  // Saves return the full listing, which supersedes any read still in flight.
  const saved = (value: SpendLimitsAdmin) => resource.replace(value)
  return <LoadGate resource={resource} label="spend limits">{data => {
    const manage = canManage && data.can_manage
    const overrides = data.limits.filter(limit => limit.kind === "user").sort((a, b) => a.subject.localeCompare(b.subject))
    const rows = overrides.filter(row => contains(search, row.subject))
    const revisionKey = singletons.map(item => data.limits.find(limit => limit.id === item.id)?.revision ?? 0).join(":")
    const tiered = new Set(data.group_limits.map(row => row.group_id))
    const untiered = data.directory_groups.filter(group => !tiered.has(group.id))
    const defaultLimit = limitText(data.limits.find(limit => limit.id === "user-default")?.limit_usd ?? null)
    const deleted = data.orphaned_group_limits
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Limits cover month-to-date model spend in US dollars, reset on the first day of each UTC month. When a limit is reached, new model requests are refused with an explanation. A finished request whose cost is still being recovered blocks new requests under an applicable limit, for up to a day. Requests still running are not counted yet, so one admitted below the threshold can exceed it.</p>
        <PageActions resource={resource} /></div>
      <SpendSummary data={data} />
      <Section id="gov-spend-limits" title="Organization and defaults" description={manage ? "Leave an amount blank for no limit. Enter 0 to block model use." : "You can view limits. Changing them requires the spend.manage permission."}>
        <LimitsForm revisionKey={revisionKey} data={data} manage={manage} onSaved={saved} onReload={resource.refresh} />
      </Section>
      <Section id="gov-spend-tiers" title="Directory group tiers"
        description="A tier replaces the default monthly limit for the active members of a provisioned directory group. Each person gets their override, else the highest tier among their directory groups (no limit is highest), else the default. Organization and session limits still apply."
        action={manage && untiered.length > 0 && <Button variant="outline" onClick={() => setTierEditor("new")}><Plus />Add tier</Button>}>
        {data.group_limits.length ? <TierRows rows={data.group_limits} canManage={manage} onEdit={setTierEditor} onRemove={setRemoveTier} />
          : !manage || data.directory_groups.length ? <p className="ns-muted">No tiers. People without an override use the default monthly limit.</p>
            : <p className="ns-muted">No directory groups yet. Groups appear after your identity provider provisions them; see <a className="ns-link" href="#settings/provisioning">Provisioning</a>.</p>}
        {deleted.length > 0 && <>
          <p className="ns-notice" role="status">{deleted.length === 1 ? "1 tier belongs to a deleted directory group and no longer applies." : `${deleted.length} tiers belong to deleted directory groups and no longer apply.`}{manage && " Remove them to free tier capacity."} A group your identity provider creates again needs a new tier.</p>
          <DeletedTierRows rows={deleted} canManage={manage} onRemove={setRemoveDeleted} />
        </>}
      </Section>
      <Section id="gov-spend-overrides" title="Per-person overrides" description="An override replaces any directory group tier and the default monthly limit for one person, across every sign-in that uses their work email."
        action={manage && <Button variant="outline" onClick={() => setEditor("new")}><Plus />Add override</Button>}>
        {overrides.length > 0 && <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search spend overrides" />}
        {rows.length ? <OverrideRows rows={rows} canManage={manage} onEdit={setEditor} onRemove={setRemove} />
          : overrides.length ? <Empty filtered noun="overrides" onClear={() => setSearch("")} /> : <p className="ns-muted">No overrides. Everyone uses their group tier or the default monthly limit.</p>}
      </Section>
      <Section id="gov-spend-lookup" title="Check a person’s limit" description="See which monthly limit applies to someone, and why, as model requests are checked.">
        <LimitLookup usage={data.usage !== null} />
      </Section>
      {editor && manage && <OverrideEditor existing={editor === "new" ? undefined : editor} overrides={overrides} onClose={() => setEditor(null)} onSaved={saved} onReload={resource.refresh} />}
      {remove && manage && <GovConfirm title={`Remove the override for ${remove.subject}?`} label="Remove override" onReload={resource.refresh} onClose={() => setRemove(null)}
        description={`They return to their directory group tier, if any, or the default monthly limit (${defaultLimit}). Spend already recorded this month still counts.`}
        onConfirm={async () => saved((await deleteSpendLimit({ path: { identity: remove.id }, query: { revision: remove.revision } })).data)} />}
      {tierEditor && manage && <TierEditor existing={tierEditor === "new" ? undefined : tierEditor} groups={untiered} onClose={() => setTierEditor(null)} onSaved={saved} onReload={resource.refresh} />}
      {removeTier && manage && <GovConfirm title={`Remove the tier for ${removeTier.group_name}?`} label="Remove tier" onReload={resource.refresh} onClose={() => setRemoveTier(null)}
        description={`Its ${members(removeTier.member_count)} return to their next highest tier, or the default monthly limit (${defaultLimit}), unless they have an override. Spend already recorded this month still counts.`}
        onConfirm={async () => saved((await deleteSpendLimit({ path: { identity: removeTier.id }, query: { revision: removeTier.revision } })).data)} />}
      {removeDeleted && manage && <GovConfirm title={`Remove the tier for deleted group ${deletedGroup(removeDeleted)}?`} label="Remove tier" onReload={resource.refresh} onClose={() => setRemoveDeleted(null)}
        description="It applies to no one, since its directory group was deleted. Removing it frees capacity for another tier."
        onConfirm={async () => saved((await deleteSpendLimit({ path: { identity: removeDeleted.id }, query: { revision: removeDeleted.revision } })).data)} />}
    </>
  }}</LoadGate>
}

function LimitsForm({ data, manage, revisionKey, onSaved, onReload }: { data: SpendLimitsAdmin; manage: boolean; revisionKey: string; onSaved: (value: SpendLimitsAdmin) => void; onReload: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const row = (key: string) => data.limits.find(limit => limit.id === key)
  const serverDrafts = () => Object.fromEntries(singletons.map(item => [item.id, usdInput(row(item.id)?.limit_usd ?? null)]))
  const [drafts, setDrafts] = useState<Record<string, string>>(serverDrafts)
  const [saved, setSaved] = useState(false), [revisions, setRevisions] = useState(revisionKey)
  // New server revisions replace the draft; a refresh at the same revisions keeps it.
  if (revisions !== revisionKey) { setRevisions(revisionKey); setDrafts(serverDrafts()) }
  let pending = 0, invalid = ""
  try { pending = spendChanges(data.limits, drafts).length } catch (reason) { invalid = reason instanceof Error ? reason.message : "Check the amounts." }
  if (!manage) return <dl className="ns-gov-limits">{singletons.map(item => <div key={item.id}><dt>{item.label}</dt><dd>{limitText(row(item.id)?.limit_usd ?? null)}<small>{item.hint}</small></dd></div>)}</dl>
  return <form onSubmit={event => { event.preventDefault(); setSaved(false); let result: SpendLimitsAdmin | undefined; void mutation.run(async () => {
    const changes = spendChanges(data.limits, drafts)
    if (changes.length) result = (await updateSpendLimits({ body: { changes } })).data
  }, () => { setSaved(true); if (result) onSaved(result); else onReload() }) }}>
    <div className="ns-gov-limit-fields">{singletons.map(item => {
      const current = row(item.id)
      return <div className="ns-field" key={item.id}><label htmlFor={`${id}-${item.id}`}>{item.label}</label>
        <div className="ns-gov-money"><span aria-hidden="true">$</span><Input id={`${id}-${item.id}`} inputMode="decimal" autoComplete="off" placeholder="No limit" disabled={mutation.busy} value={drafts[item.id] ?? ""}
          aria-describedby={`${id}-${item.id}-hint`} onChange={event => { setSaved(false); setDrafts(previous => ({ ...previous, [item.id]: event.target.value })) }} /></div>
        <p id={`${id}-${item.id}-hint`} className="ns-field-hint">{item.hint} Current: {limitText(current?.limit_usd ?? null)}{current?.updated_at ? ` · Updated ${dateTime(current.updated_at)}` : ""}</p></div>
    })}</div>
    {invalid && <p className="ns-error" role="alert">{invalid}</p>}
    <MutationError mutation={mutation} onReload={onReload} />
    <div className="ns-row-actions"><Button type="submit" disabled={mutation.busy || Boolean(invalid) || !pending}>{mutation.busy ? "Saving…" : "Save limits"}</Button>
      <span className="ns-muted" role="status">{saved ? "Limits saved." : pending ? `${pending === 1 ? "1 unsaved change" : `${pending} unsaved changes`}.` : ""}</span></div>
  </form>
}

function OverrideEditor({ existing, overrides, onClose, onSaved, onReload }: { existing?: SpendLimit; overrides: readonly SpendLimit[]; onClose: () => void; onSaved: (value: SpendLimitsAdmin) => void; onReload: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [email, setEmail] = useState(existing?.subject ?? ""), [amount, setAmount] = useState(usdInput(existing?.limit_usd ?? null))
  return <GovDialog title={existing ? `Edit limit for ${existing.subject}` : "Add a per-person override"} busy={mutation.busy} onClose={onClose}
    description="The override replaces any directory group tier and the default monthly limit for this person. Their spend this month still counts toward the organization limit.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); let result: SpendLimitsAdmin; void mutation.run(async () => {
      const change = overrideChange(email, amount, existing)
      if (!existing && overrides.some(row => row.id === change.id)) throw new Error("This person already has an override. Edit it instead.")
      result = (await updateSpendLimits({ body: { changes: [change] } })).data
    }, () => { onSaved(result); onClose() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-email`}>Work email</label><Input id={`${id}-email`} type="email" required autoFocus={!existing} maxLength={254} autoComplete="off" disabled={mutation.busy || Boolean(existing)} value={email} onChange={event => setEmail(event.target.value)} /></div>
      <div className="ns-field"><label htmlFor={`${id}-amount`}>Monthly limit (USD)</label>
        <div className="ns-gov-money"><span aria-hidden="true">$</span><Input id={`${id}-amount`} inputMode="decimal" autoFocus={Boolean(existing)} autoComplete="off" placeholder="No limit" disabled={mutation.busy} value={amount} aria-describedby={`${id}-amount-hint`} onChange={event => setAmount(event.target.value)} /></div>
        <p id={`${id}-amount-hint`} className="ns-field-hint">Leave blank to give this person no monthly limit, even when a default applies. Enter 0 to block their model use.</p></div>
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel={existing ? "Save limit" : "Add override"} />
    </form>
  </GovDialog>
}

function TierEditor({ existing, groups, onClose, onSaved, onReload }: { existing?: SpendTier; groups: readonly DirectoryGroup[]; onClose: () => void; onSaved: (value: SpendLimitsAdmin) => void; onReload: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [groupId, setGroupId] = useState(existing?.group_id ?? groups[0]?.id ?? "")
  const [amount, setAmount] = useState(usdInput(existing?.limit_usd ?? null)), [confirming, setConfirming] = useState(false)
  const name = existing?.group_name ?? groups.find(group => group.id === groupId)?.display_name ?? "this group"
  let unlimited = false
  try { unlimited = parseUsd(amount) === null } catch { /* The save reports the amount's error. */ }
  return <GovDialog title={existing ? `Edit tier for ${existing.group_name}` : "Add a directory group tier"} busy={mutation.busy} onClose={onClose}
    description="The tier replaces the default monthly limit for the group’s active members who have no override. Someone in several tiered groups gets the highest.">
    <form className="ns-fields" onSubmit={event => {
      event.preventDefault()
      // No limit exempts every member from the default, so it needs a second, explicit save.
      if (unlimited && !confirming) { setConfirming(true); return }
      let result: SpendLimitsAdmin
      void mutation.run(async () => { result = (await updateSpendLimits({ body: { changes: [tierChange(groupId, amount, existing)] } })).data }, () => { onSaved(result); onClose() })
    }}>
      {!existing && <div className="ns-field"><label htmlFor={`${id}-group`}>Directory group</label>
        <Choice id={`${id}-group`} label="Directory group" value={groupId} disabled={mutation.busy} onChange={value => { setGroupId(value); setConfirming(false) }}
          options={groups.map(group => ({ value: group.id, label: `${group.display_name} · ${members(group.member_count)}` }))} /></div>}
      <div className="ns-field"><label htmlFor={`${id}-amount`}>Monthly limit per person (USD)</label>
        <div className="ns-gov-money"><span aria-hidden="true">$</span><Input id={`${id}-amount`} inputMode="decimal" autoFocus={Boolean(existing)} autoComplete="off" placeholder="No limit" disabled={mutation.busy} value={amount}
          aria-describedby={`${id}-amount-hint`} onChange={event => { setAmount(event.target.value); setConfirming(false) }} /></div>
        <p id={`${id}-amount-hint`} className="ns-field-hint">Leave blank for no limit: members are then exempt from the default. $0 blocks members who are in no higher tier; use a $0 override to block one person.</p></div>
      {confirming && <p className="ns-notice" role="alert">Save {name} without a limit? Its active members without an override will have no monthly limit, whatever the default.</p>}
      <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} disabled={!groupId} submitLabel={confirming ? "Save without a limit" : existing ? "Save tier" : "Add tier"} />
    </form>
  </GovDialog>
}

function LimitLookup({ usage }: { usage: boolean }) {
  const mutation = useGovMutation(), id = useId()
  const [email, setEmail] = useState(""), [result, setResult] = useState<EffectiveSpendLimit | null>(null)
  return <form className="ns-gov-lookup" onSubmit={event => {
    event.preventDefault(); setResult(null)
    let found: EffectiveSpendLimit
    void mutation.run(async () => { found = (await getEffectiveSpendLimit({ query: { email: normalizeEmail(email) } })).data }, () => setResult(found))
  }}>
    <div className="ns-field"><label htmlFor={`${id}-email`}>Work email</label>
      <div className="ns-gov-lookup-row"><Input id={`${id}-email`} type="email" required maxLength={254} autoComplete="off" value={email} onChange={event => setEmail(event.target.value)} />
        <Button type="submit" variant="outline" disabled={mutation.busy || !email.trim()}><Search />{mutation.busy ? "Checking…" : "Check limit"}</Button></div></div>
    <MutationError mutation={mutation} />
    {result && <dl className="ns-gov-limits" aria-label={`Spend limit for ${result.email}`}>
      <div><dt>Monthly limit for {result.email}</dt><dd>{limitText(result.limit_usd)}<small>{limitSourceText(result.source, result.group_name)}</small></dd></div>
      {usage && <div><dt>Spent this month</dt><dd>{result.used_usd === null ? "Pending cost reconciliation" : usd(result.used_usd)}</dd></div>}
    </dl>}
  </form>
}
