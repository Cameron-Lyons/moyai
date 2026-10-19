import { api } from "./api"

export function saveBlob(blob: Blob, filename: string): void {
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = objectUrl
  link.download = filename
  document.body.append(link)
  try {
    link.click()
  } finally {
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0)
  }
}

export async function downloadDebugTrace(sessionId: string): Promise<void> {
  const trajectory = await api<object>(`/sessions/${encodeURIComponent(sessionId)}/debug-trace`)
  saveBlob(new Blob([JSON.stringify(trajectory, null, 2)], { type: "application/json" }), `moyai-trace-${sessionId}.json`)
}
