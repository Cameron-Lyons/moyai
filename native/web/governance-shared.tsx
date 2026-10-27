import React, { useCallback, useEffect, useRef, useState } from "react"
import { Check, Copy, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { ApiError, csrfToken } from "./api"
import { dateTime, errorText } from "./settings"
import { actionLabel, detailText } from "./governance-data"
import type { AuditEntry } from "./generated/api"

export const STALE_MESSAGE = "This changed elsewhere. Reload and try again."
export type GovResource<T> = { data: T | undefined; loading: boolean; error: string; status: number; refresh: () => void }

export const accessChanged = () => window.dispatchEvent(new Event("moyai:access-changed"))
/** Unwrap a generated SDK result: `.then(dataOf)`. */
export const dataOf = <T,>(result: { data: T }): T => result.data

/**
 * Keyed read through a generated SDK loader. `name` identifies what `load`
 * reads (include its parameters); responses from an earlier name, actor,
 * refresh or replacement are dropped.
 */
export function useGovResource<T>(name: string | null, load: (signal: AbortSignal) => Promise<T>): GovResource<T> & { replace: (data: T) => void } {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<{ key: string; data?: T; loading: boolean; error: string; status: number }>({ key: "", loading: Boolean(name), error: "", status: 0 })
  const replaced = useRef(0)
  const key = name ? `${name}#${csrfToken()}` : ""
  useEffect(() => {
    if (!name) { setState({ key, loading: false, error: "", status: 0 }); return }
    const controller = new AbortController(), generation = replaced.current
    const stale = () => controller.signal.aborted || replaced.current !== generation
    setState(previous => ({ key, data: previous.key === key ? previous.data : undefined, loading: true, error: "", status: 0 }))
    // `load` belongs to the render that produced this key, so it reads what `name` names.
    void load(controller.signal).then(
      data => { if (!stale()) setState({ key, data, loading: false, error: "", status: 200 }) },
      reason => {
        if (stale()) return
        const status = reason instanceof ApiError ? reason.status : 0
        // Protected data is discarded on every failure, not only on 403.
        setState({ key, loading: false, error: errorText(reason), status })
        if (status === 403) accessChanged()
      },
    )
    return () => controller.abort()
  }, [key, name, revision])
  const refresh = useCallback(() => setRevision(value => value + 1), [])
  // A mutation that returns the full listing supersedes any read still in flight.
  const replace = useCallback((data: T) => { replaced.current++; setState({ key, data, loading: false, error: "", status: 200 }) }, [key])
  const current = state.key === key
  return { data: current ? state.data : undefined, loading: !current || state.loading, error: current ? state.error : "", status: current ? state.status : 0, refresh, replace }
}

export type GovMutation = { busy: boolean; error: string; conflict: boolean; reset: () => void; run: (action: () => Promise<unknown>, done?: () => void) => Promise<boolean> }
/** Single-flight mutation; 403 re-reads access, 409 offers a reload. */
export function useGovMutation(): GovMutation {
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<{ error: string; conflict: boolean }>({ error: "", conflict: false })
  const alive = useRef(true), pending = useRef(false)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const run = async (action: () => Promise<unknown>, done?: () => void) => {
    if (pending.current) return false
    const auth = csrfToken()
    pending.current = true; setBusy(true); setFailure({ error: "", conflict: false })
    try {
      await action()
      if (alive.current && csrfToken() === auth) done?.()
      return true
    } catch (reason) {
      if (alive.current && csrfToken() === auth) {
        const status = reason instanceof ApiError ? reason.status : 0
        setFailure({ error: status === 409 ? (reason instanceof Error && reason.message) || STALE_MESSAGE : errorText(reason), conflict: status === 409 })
        if (status === 403) accessChanged()
      }
      return false
    } finally { pending.current = false; if (alive.current) setBusy(false) }
  }
  return { busy, error: failure.error, conflict: failure.conflict, reset: () => setFailure({ error: "", conflict: false }), run }
}

export function MutationError({ mutation, onReload }: { mutation: Pick<GovMutation, "error" | "conflict">; onReload?: () => void }) {
  if (!mutation.error) return null
  return <div className="ns-error ns-gov-error" role="alert"><span>{mutation.error}</span>
    {mutation.conflict && onReload && <Button type="button" variant="outline" size="sm" onClick={onReload}><RefreshCw />Reload</Button>}</div>
}

/** A failed load-more page: lost access (403) drops loaded pages now and re-reads access and the gated first page. */
export function loadMoreFailed(reason: unknown, resource: { refresh: () => void }, clear: () => void, show: (error: string) => void) {
  if (reason instanceof ApiError && reason.status === 403) { clear(); accessChanged(); resource.refresh() }
  else show(errorText(reason))
}

/** Settings dialog shell: labelled, cancellable, contained scrolling and focus return. */
export function GovDialog({ title, description, busy = false, onClose, children, wide = false, dismissible = true }: {
  title: string; description: React.ReactNode; busy?: boolean; onClose: () => void; children: React.ReactNode; wide?: boolean; dismissible?: boolean
}) {
  const opener = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null)
  const block = (event: Event) => { if (!dismissible || busy) event.preventDefault() }
  return <Dialog open onOpenChange={open => { if (!open && !busy && dismissible) onClose() }}>
    <DialogContent className={`native-settings-dialog${wide ? " ns-gov-wide" : ""}`} showCloseButton={dismissible}
      onEscapeKeyDown={block} onInteractOutside={block}
      onCloseAutoFocus={event => { event.preventDefault(); if (opener.current?.isConnected) opener.current.focus() }}>
      <DialogHeader><DialogTitle>{title}</DialogTitle><DialogDescription>{description}</DialogDescription></DialogHeader>
      {children}
    </DialogContent>
  </Dialog>
}

export function DialogActions({ busy, onCancel, submitLabel, busyLabel = "Saving…", disabled = false, destructive = false, onSubmit }: {
  busy: boolean; onCancel: () => void; submitLabel: string; busyLabel?: string; disabled?: boolean; destructive?: boolean; onSubmit?: () => void
}) {
  return <div className="ns-dialog-actions"><Button type="button" variant="outline" disabled={busy} onClick={onCancel}>Cancel</Button>
    <Button type={onSubmit ? "button" : "submit"} variant={destructive ? "destructive" : "default"} disabled={busy || disabled} onClick={onSubmit}>{busy ? busyLabel : submitLabel}</Button></div>
}

/** Confirmation with an explained effect and conflict reload; destructive unless `destructive={false}`. */
export function GovConfirm({ title, description, label, busyLabel, destructive = true, onConfirm, onClose, onReload }: {
  title: string; description: React.ReactNode; label: string; busyLabel?: string; destructive?: boolean; onConfirm: () => Promise<unknown>; onClose: () => void; onReload: () => void
}) {
  const mutation = useGovMutation()
  return <GovDialog title={title} description={description} busy={mutation.busy} onClose={onClose}>
    <MutationError mutation={mutation} onReload={() => { onReload(); onClose() }} />
    <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel={label} busyLabel={busyLabel} destructive={destructive} onSubmit={() => void mutation.run(onConfirm, onClose)} />
  </GovDialog>
}

export function Section({ title, description, action, children, id }: { title: string; description?: React.ReactNode; action?: React.ReactNode; children: React.ReactNode; id?: string }) {
  return <section className="ns-gov-section" aria-labelledby={id ? `${id}-title` : undefined}>
    <div className="ns-gov-section-heading"><div><h2 id={id ? `${id}-title` : undefined}>{title}</h2>{description && <p className="ns-muted">{description}</p>}</div>{action && <div className="ns-row-actions">{action}</div>}</div>
    {children}
  </section>
}

export function PageActions({ resource, children }: { resource: { loading: boolean; refresh: () => void }; children?: React.ReactNode }) {
  return <div className="ns-gov-page-actions">{children}<Button type="button" variant="outline" disabled={resource.loading} onClick={resource.refresh}><RefreshCw size={16} />Refresh</Button></div>
}

export function LoadGate<T>({ resource, label, children }: { resource: GovResource<T>; label: string; children: (data: T) => React.ReactNode }) {
  if (resource.error) return <div className="ns-empty" role="alert"><h2>Unable to load {label}</h2><p>{resource.error}</p>
    {resource.status === 403 ? <p className="ns-muted">Your access may have changed. Settings will update when your permissions are confirmed.</p> : null}
    <Button variant="outline" onClick={resource.refresh}><RefreshCw />Try again</Button></div>
  if (!resource.data) return <p className="ns-muted" role="status">Loading {label}…</p>
  return <div aria-busy={resource.loading}>{children(resource.data)}</div>
}

/** secret marks a one-time credential; mono shows code, such as a command, in the monospace font. */
export function CopyField({ id, label, value, hint, secret = false, mono = false, autoFocus = false }: { id: string; label: string; value: string; hint?: string; secret?: boolean; mono?: boolean; autoFocus?: boolean }) {
  const [status, setStatus] = useState("")
  const input = useRef<HTMLInputElement>(null), reset = useRef(0)
  useEffect(() => () => window.clearTimeout(reset.current), [])
  const copy = async () => {
    window.clearTimeout(reset.current)
    try { await navigator.clipboard.writeText(value); setStatus("Copied to the clipboard."); reset.current = window.setTimeout(() => setStatus(""), 3000) }
    catch { input.current?.select(); setStatus("Clipboard access is unavailable. The text is selected; copy it with your keyboard.") }
  }
  return <div className="ns-field ns-gov-copy">
    <label htmlFor={id}>{label}</label>
    <div className="ns-gov-copy-row"><Input ref={input} id={id} readOnly autoFocus={autoFocus} value={value} spellCheck={false} autoComplete="off" className={secret ? "ns-gov-secret" : mono ? "ns-gov-mono" : undefined}
      aria-describedby={hint ? `${id}-hint` : undefined} onFocus={event => event.currentTarget.select()} />
      <Button type="button" variant="outline" onClick={() => void copy()}>{status.startsWith("Copied") ? <Check /> : <Copy />}Copy<span className="visually-hidden"> {label}</span></Button></div>
    {hint && <p id={`${id}-hint`} className="ns-field-hint">{hint}</p>}
    <p className={status ? "ns-field-hint" : "visually-hidden"} role="status">{status}</p>
  </div>
}

export function AuditDetails({ entry }: { entry: AuditEntry }) {
  const rows = Object.entries(entry.details ?? {})
  if (!rows.length) return <span className="ns-muted">No details</span>
  return <details><summary>Details<span className="visually-hidden"> for {actionLabel(entry.action)} at {dateTime(entry.created_at)}</span></summary>
    <dl className="ns-gov-details">{rows.map(([key, value]) => <React.Fragment key={key}><dt>{key.replace(/_/g, " ")}</dt><dd>{detailText(value)}</dd></React.Fragment>)}</dl></details>
}

export function ActivityList({ entries, empty }: { entries: readonly AuditEntry[]; empty: string }) {
  if (!entries.length) return <p className="ns-muted">{empty}</p>
  return <ul className="ns-gov-activity">{entries.map(entry => <li key={`${entry.source}:${entry.id}`}>
    <div><strong>{actionLabel(entry.action)}</strong><span>{entry.resource_type} · {entry.resource_id}</span></div>
    <small>{entry.actor || "System"} · <time dateTime={entry.created_at}>{dateTime(entry.created_at)}</time></small>
  </li>)}</ul>
}

/** Status text is always written out; color only reinforces it. */
export function StatusBadge({ tone, children }: { tone: "success" | "warning" | "danger" | "neutral"; children: React.ReactNode }) {
  return <span className={`ns-badge${tone === "neutral" ? "" : ` ns-${tone}`}`}>{children}</span>
}
