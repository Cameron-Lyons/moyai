import { useEffect, useId, useRef, useState } from "react"
import { Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { TableCell, TableRow } from "@/components/ui/table"
import { ApiError, apiDownload, csrfToken } from "./api"
import { saveBlob } from "./debug-trace"
import { Choice, RecordTable, dateTime, errorText } from "./settings"
import { actionLabel, auditExportPath, auditOutcome, auditPageQuery, auditQuery, emptyAuditFilters, resourceTypeLabel } from "./governance-data"
import { AuditDetails, LoadGate, MutationError, PageActions, StatusBadge, accessChanged, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import { listGovernanceAudit, type AuditEntry, type AuditFacets, type AuditPage as AuditResponse } from "./generated/api"
import type { AuditExportFormat, AuditFilters } from "./governance-types"

const ALL = "__all__"
const sourceLabels: Record<AuditEntry["source"], string> = { activity: "Activity", governance: "Governance", user_roles: "Built-in roles", connections: "Connections", credentials: "Credentials" }

function Outcome({ entry }: { entry: AuditEntry }) {
  const outcome = auditOutcome(entry)
  if (!outcome) return null
  return <StatusBadge tone={outcome === "denied" ? "danger" : "warning"}>{outcome === "denied" ? "Denied" : "Failed"}</StatusBadge>
}

export function AuditRows({ entries }: { entries: AuditEntry[] }) {
  return <RecordTable label="Audit log entries" headings={["When", "Action", "Actor", "Resource", "Details"]}>{entries.map(entry => <TableRow key={`${entry.source}:${entry.id}`}>
    <TableCell><time dateTime={entry.created_at}>{dateTime(entry.created_at)}</time></TableCell>
    <TableCell><strong>{actionLabel(entry.action)}</strong> <Outcome entry={entry} /><small><code>{entry.action}</code> · {sourceLabels[entry.source] ?? entry.source}</small></TableCell>
    <TableCell>{entry.actor || "System"}</TableCell>
    <TableCell>{entry.resource_type}<small>{entry.resource_id}</small></TableCell>
    <TableCell><AuditDetails entry={entry} /></TableCell>
  </TableRow>)}</RecordTable>
}

const filtered = (filters: AuditFilters) => Object.values(filters).some(Boolean)

export function AuditLogPage() {
  const id = useId()
  const [draft, setDraft] = useState<AuditFilters>(emptyAuditFilters)
  const [applied, setApplied] = useState<AuditFilters>(emptyAuditFilters)
  const [formError, setFormError] = useState("")
  const query = auditPageQuery(applied)
  const resource = useGovResource(`audit:${JSON.stringify(query)}`, signal => listGovernanceAudit({ query, signal }).then(dataOf))
  const [facets, setFacets] = useState<AuditFacets>({ actions: [], resource_types: [] })
  const [pages, setPages] = useState<{ base?: AuditResponse; entries: AuditEntry[]; next: string | null; loaded: boolean; loading: boolean; error: string }>({ entries: [], next: null, loaded: false, loading: false, error: "" })
  const loadMore = useRef<AbortController | null>(null), exportAbort = useRef<AbortController | null>(null)
  const exporter = useGovMutation(), [format, setFormat] = useState<AuditExportFormat>("csv")
  useEffect(() => { if (resource.data?.facets) setFacets(resource.data.facets) }, [resource.data])
  // New filters or a refresh discard pages loaded for the previous result.
  useEffect(() => { loadMore.current?.abort(); setPages({ base: resource.data, entries: [], next: null, loaded: false, loading: false, error: "" }) }, [resource.data])
  // Leaving the page stops paging and any export still streaming.
  useEffect(() => () => { loadMore.current?.abort(); exportAbort.current?.abort() }, [])
  const change = (patch: Partial<AuditFilters>) => { setFormError(""); setDraft(previous => ({ ...previous, ...patch })) }
  const apply = (next: AuditFilters) => {
    try { auditQuery(next) } catch (reason) { setFormError(reason instanceof Error ? reason.message : "Check the filters."); return }
    setFormError(""); exporter.reset(); setApplied(next)
  }
  const download = (value: AuditExportFormat) => {
    let file: { blob: Blob; filename: string }
    setFormat(value)
    // Exports are single-flight, so no earlier controller is still live here.
    void exporter.run(async () => { exportAbort.current = new AbortController(); file = await apiDownload(auditExportPath(applied, value), exportAbort.current.signal) },
      () => saveBlob(file.blob, file.filename || `governance.${value}`))
  }
  const clear = () => { setDraft(emptyAuditFilters); apply(emptyAuditFilters) }
  const options = (values: string[], current: string, all: string, label: (value: string) => string) =>
    [{ value: ALL, label: all }, ...[...new Set([...values, ...(current ? [current] : [])])].map(value => ({ value, label: label(value) }))]
  return <>
    <form className="ns-gov-filters" aria-label="Audit log filters" noValidate onSubmit={event => { event.preventDefault(); apply(draft) }}>
      <div className="ns-field"><label htmlFor={`${id}-action`}>Action</label><Choice id={`${id}-action`} label="Action" value={draft.action || ALL} onChange={value => change({ action: value === ALL ? "" : value })} options={options(facets.actions, draft.action, "All actions", actionLabel)} /></div>
      <div className="ns-field"><label htmlFor={`${id}-resource`}>Resource type</label><Choice id={`${id}-resource`} label="Resource type" value={draft.resource_type || ALL} onChange={value => change({ resource_type: value === ALL ? "" : value })} options={options(facets.resource_types, draft.resource_type, "All resource types", resourceTypeLabel)} /></div>
      <div className="ns-field"><label htmlFor={`${id}-actor`}>Actor email</label><Input id={`${id}-actor`} type="email" autoComplete="off" maxLength={254} placeholder="name@example.com" value={draft.actor} onChange={event => change({ actor: event.target.value })} /></div>
      <div className="ns-field"><label htmlFor={`${id}-from`}>From (UTC)</label><Input id={`${id}-from`} type="date" value={draft.from} max={draft.to || undefined} onChange={event => change({ from: event.target.value })} /></div>
      <div className="ns-field"><label htmlFor={`${id}-to`}>To (UTC)</label><Input id={`${id}-to`} type="date" value={draft.to} min={draft.from || undefined} onChange={event => change({ to: event.target.value })} /></div>
      <div className="ns-gov-filter-actions"><Button type="submit">Apply filters</Button>{(filtered(draft) || filtered(applied)) && <Button type="button" variant="outline" onClick={clear}>Clear filters</Button>}</div>
      {formError && <p className="ns-error" role="alert">{formError}</p>}
    </form>
    <div className="ns-gov-export" role="group" aria-label="Export the filtered audit log" aria-describedby={`${id}-export-hint`}>
      <span className="ns-muted">Export {filtered(applied) ? "the filtered" : "the full"} history, newest first:</span>
      <Button variant="outline" size="sm" disabled={exporter.busy} onClick={() => download("csv")}><Download />{exporter.busy && format === "csv" ? "Exporting…" : "Export CSV"}</Button>
      <Button variant="outline" size="sm" disabled={exporter.busy} onClick={() => download("ndjson")}><Download />{exporter.busy && format === "ndjson" ? "Exporting…" : "Export NDJSON"}</Button>
      <PageActions resource={resource} />
      <p id={`${id}-export-hint`} className="ns-field-hint ns-gov-export-hint">An export stops at 50,000 entries. A capped file ends with an <code>export.truncated</code> row instead of the older entries, and its <code>next_before</code> shows where it stopped: set To (UTC) to the day before that date to export older days. The rest of that day needs the audit export API with <code>before</code> set to <code>next_before</code>.</p>
    </div>
    <MutationError mutation={exporter} />
    <LoadGate resource={resource} label="the audit log">{data => {
      const current = pages.base === data
      const entries = [...data.entries, ...(current ? pages.entries : [])]
      const next = current && pages.loaded ? pages.next : data.next_cursor
      const more = () => {
        if (!next || pages.loading) return
        const controller = new AbortController(), auth = csrfToken()
        loadMore.current?.abort(); loadMore.current = controller
        setPages(previous => ({ ...previous, loading: true, error: "" }))
        void listGovernanceAudit({ query: auditPageQuery(applied, next), signal: controller.signal }).then(({ data: page }) => {
          if (controller.signal.aborted || auth !== csrfToken()) return
          setPages(previous => previous.base === data ? { base: data, entries: [...previous.entries, ...page.entries], next: page.next_cursor, loaded: true, loading: false, error: "" } : previous)
        }, reason => {
          if (controller.signal.aborted) return
          if (reason instanceof ApiError && reason.status === 403) {
            // Lost access: drop loaded pages now, re-read access and the gated first page.
            setPages({ entries: [], next: null, loaded: false, loading: false, error: "" })
            accessChanged(); resource.refresh(); return
          }
          setPages(previous => ({ ...previous, loading: false, error: errorText(reason) }))
        })
      }
      return <>
        <p className="ns-muted ns-gov-count" role="status">{entries.length.toLocaleString()} {entries.length === 1 ? "entry" : "entries"} shown{next ? "; more are available" : ""}.</p>
        {entries.length ? <AuditRows entries={entries} /> : <div className="ns-empty"><h2>{filtered(applied) ? "No matching audit entries" : "No audit entries yet"}</h2>
          <p>{filtered(applied) ? "Try a wider date range or clear the filters." : "Sign-ins, session activity, policy denials, and role, provisioning, policy, spend, connection and credential changes appear here as they happen."}</p>
          {filtered(applied) && <Button variant="outline" onClick={clear}>Clear filters</Button>}</div>}
        {pages.error && <p className="ns-error" role="alert">{pages.error}</p>}
        {next && <Button className="ns-gov-more" variant="outline" disabled={pages.loading} onClick={more}>{pages.loading ? "Loading entries…" : "Load more"}</Button>}
      </>
    }}</LoadGate>
  </>
}
