let csrf = ""
export const setCsrf = (value: string) => { csrf = value }
export const csrfToken = () => csrf

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); this.name = "Error" }
}

function detailMessage(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || !("detail" in value)) return
  const detail = value.detail
  if (typeof detail === "string" && detail.trim()) return detail
  if (Array.isArray(detail) && typeof detail[0]?.msg === "string") return detail[0].msg
}

function responseFailure(status: number): string {
  if (status === 401) return "Your session has expired. Please sign in again."
  if (status === 403) return "You no longer have access to this request."
  if (status >= 500) return `Moyai is temporarily unavailable (HTTP ${status}). Please try again.`
  return `The request could not be completed (HTTP ${status}). Please try again.`
}

const aborted = (error: unknown, signal?: AbortSignal | null) => signal?.aborted || (error instanceof Error && error.name === "AbortError")

/** One attempt only: callers must not silently replay a possibly accepted write. */
async function send(path: string, options: RequestInit): Promise<Response> {
  const requestCsrf = csrf
  const headers = new Headers(options.headers)
  headers.set("X-Moyai-CSRF", requestCsrf)
  headers.set("X-CSRF-Token", requestCsrf)
  let response: Response
  try {
    response = await fetch(`/api${path}`, { ...options, headers })
  } catch (error) {
    if (aborted(error, options.signal)) throw error
    throw new ApiError("Could not reach Moyai. Check your connection and try again.", 0)
  }
  if (response.ok) return response
  let value: unknown
  try {
    value = await response.json()
  } catch (error) {
    // Error pages and empty error bodies must retain their HTTP status. Never
    // show their raw text/HTML (which may contain proxy or backend details).
    if (aborted(error, options.signal)) throw error
  }
  if (response.status === 401 && csrf === requestCsrf) window.dispatchEvent(new Event("moyai:signed-out"))
  throw new ApiError(detailMessage(value) ?? responseFailure(response.status), response.status)
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  const response = await send(path, { ...options, headers })
  if (response.status === 204 || response.status === 205 || options.method === "HEAD") return undefined as T
  try {
    return await response.json() as T
  } catch (error) {
    if (aborted(error, options.signal)) throw error
    throw new ApiError("Moyai returned an unreadable response. Please try again.", response.status)
  }
}

/** File download with the same headers and error policy; the name comes from Content-Disposition. */
export async function apiDownload(path: string): Promise<{ blob: Blob; filename: string }> {
  const response = await send(path, {})
  return { blob: await response.blob(), filename: /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") ?? "")?.[1] ?? "" }
}

export function api<T>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> {
  return apiRequest<T>(path, { method, signal, body: body === undefined ? undefined : JSON.stringify(body) })
}
