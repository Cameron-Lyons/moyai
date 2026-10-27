import { useEffect, useRef, useState } from "react"
import { CircleAlert, Clock3, Gauge } from "lucide-react"
import { csrfToken } from "./api"
import { getSpendStatus, type PersonalSpendStatus } from "./generated/api"
import { spendNotice } from "./governance-data"
import "./spend-status.css"

// Focus refreshes at most this often; failures, sign-in changes and refreshKey reload at once.
const FOCUS_REFRESH_MS = 5 * 60_000
const icons = { warning: Gauge, reached: CircleAlert, pending: Clock3 }

/**
 * The person's monthly model budget, computed live by GET /api/spend/status.
 * Advisory only: admission refuses requests whether or not this is shown, so
 * a failed read hides the notice. refreshKey changes reload it (a failed turn).
 */
export function SpendStatusNotice({ refreshKey = "" }: { refreshKey?: string }) {
  const [status, setStatus] = useState<{ auth: string; value: PersonalSpendStatus } | null>(null)
  const [revision, setRevision] = useState(0)
  const loadedAt = useRef(0)
  useEffect(() => {
    const focused = () => { if (Date.now() - loadedAt.current >= FOCUS_REFRESH_MS) setRevision(value => value + 1) }
    window.addEventListener("focus", focused)
    return () => window.removeEventListener("focus", focused)
  }, [])
  useEffect(() => {
    const controller = new AbortController(), auth = csrfToken()
    loadedAt.current = Date.now()
    void getSpendStatus({ signal: controller.signal }).then(({ data }) => {
      if (!controller.signal.aborted && csrfToken() === auth) setStatus({ auth, value: data })
    }, () => { if (!controller.signal.aborted) setStatus(null) })
    return () => controller.abort()
  }, [refreshKey, revision])
  const notice = status && status.auth === csrfToken() ? spendNotice(status.value) : null
  if (!notice) return null
  const Icon = icons[notice.tone]
  return <p className={`spend-status ${notice.tone === "reached" ? "error" : "notice"}`} role="status">
    <Icon size={15} aria-hidden="true" /><span>{notice.text}</span>
  </p>
}
