import { useId, useState } from "react"
import { Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { TableCell, TableRow } from "@/components/ui/table"
import { Empty, RecordTable, Toolbar, contains, dateTime } from "./settings"
import { limitText, overrideChange, spendChanges, usd, usdInput } from "./governance-data"
import { DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import { deleteSpendLimit, getSpendLimits, updateSpendLimits, type SpendLimitView as SpendLimit, type SpendLimitsAdmin } from "./generated/api"

const singletons = [
  { id: "organization", label: "Organization monthly limit", hint: "Total model spend for everyone this calendar month (UTC)." },
  { id: "user-default", label: "Default monthly limit per person", hint: "Applies to each person without an override below." },
  { id: "session-default", label: "Limit per session", hint: "Lifetime model spend for a session and all its delegated agents." },
] as const
const monthStart = (value: string) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" }) : "the start of this month"
const requests = (count: number) => count === 1 ? "1 model request" : `${count} model requests`

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

export function SpendLimitsPage({ canManage }: { canManage: boolean }) {
  const resource = useGovResource("spend-limits", signal => getSpendLimits({ signal }).then(dataOf))
  const [search, setSearch] = useState("")
  const [editor, setEditor] = useState<SpendLimit | "new" | null>(null), [remove, setRemove] = useState<SpendLimit | null>(null)
  // Saves return the full listing, which supersedes any read still in flight.
  const saved = (value: SpendLimitsAdmin) => resource.replace(value)
  return <LoadGate resource={resource} label="spend limits">{data => {
    const manage = canManage && data.can_manage
    const overrides = data.limits.filter(limit => limit.kind === "user").sort((a, b) => a.subject.localeCompare(b.subject))
    const rows = overrides.filter(row => contains(search, row.subject))
    const revisionKey = singletons.map(item => data.limits.find(limit => limit.id === item.id)?.revision ?? 0).join(":")
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Limits cover month-to-date model spend in US dollars, reset on the first day of each UTC month. When a limit is reached, new model requests are refused with an explanation. A finished request whose cost is still being recovered blocks new requests under an applicable limit, for up to a day. Requests still running are not counted yet, so one admitted below the threshold can exceed it.</p>
        <PageActions resource={resource} /></div>
      <SpendSummary data={data} />
      <Section id="gov-spend-limits" title="Organization and defaults" description={manage ? "Leave an amount blank for no limit. Enter 0 to block model use." : "You can view limits. Changing them requires the spend.manage permission."}>
        <LimitsForm revisionKey={revisionKey} data={data} manage={manage} onSaved={saved} onReload={resource.refresh} />
      </Section>
      <Section id="gov-spend-overrides" title="Per-person overrides" description="An override replaces the default monthly limit for one person, across every sign-in that uses their work email."
        action={manage && <Button variant="outline" onClick={() => setEditor("new")}><Plus />Add override</Button>}>
        {overrides.length > 0 && <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search spend overrides" />}
        {rows.length ? <OverrideRows rows={rows} canManage={manage} onEdit={setEditor} onRemove={setRemove} />
          : overrides.length ? <Empty filtered noun="overrides" onClear={() => setSearch("")} /> : <p className="ns-muted">No overrides. Everyone uses the default monthly limit.</p>}
      </Section>
      {editor && manage && <OverrideEditor existing={editor === "new" ? undefined : editor} overrides={overrides} onClose={() => setEditor(null)} onSaved={saved} onReload={resource.refresh} />}
      {remove && manage && <GovConfirm title={`Remove the override for ${remove.subject}?`} label="Remove override" onReload={resource.refresh} onClose={() => setRemove(null)}
        description={`They return to the default monthly limit (${limitText(data.limits.find(limit => limit.id === "user-default")?.limit_usd ?? null)}). Spend already recorded this month still counts.`}
        onConfirm={async () => saved((await deleteSpendLimit({ path: { identity: remove.id }, query: { revision: remove.revision } })).data)} />}
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
    description="The override replaces the default monthly limit for this person. Their spend this month still counts toward the organization limit.">
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
