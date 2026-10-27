import React, { useEffect, useRef, useState } from "react"
import { ArrowUpRight, Bug, Clock3, Code2, Globe, ListChecks, LockKeyhole, Search, Send } from "lucide-react"
import { Button } from "@/components/ui/button"
import { SkillComposer } from "./skill-composer"
import { GoalChip, goalCommandAction } from "./goal"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SpaceBackdrop } from "./space-backdrop"
import { SpendStatusNotice } from "./spend-status"
import "./home.css"
import { ApiError, csrfToken } from "./api"
import { AttachButton, AttachmentPreviews, useAttachments, useFileDrop, FileDropOverlay } from "./attachments"
import type { GeneralPreferences } from "./general-preferences"
import type { NewConversation, Session } from "./conversation-state"
import { createSession, createSessionMessage, getNewSessionSecurityPolicy, listConnections, listSecurityProfileOptions, type ConnectionView, type NewSession, type NewSessionSecurityPolicy, type SessionProfileCatalog } from "./generated/api"
import { policyAdmitsConnection, policyModel, policyModels } from "./security-policy"

type HomeConnection = Pick<ConnectionView, "id" | "name" | "kind" | "enabled" | "shared" | "read_only" | "policy">
const starters = [
  { label: "Review code", detail: "Find the edge cases", prompt: "Review my changes for bugs and improvements.", Icon: Code2 },
  { label: "Fix a bug", detail: "Trace it to the source", prompt: "Help me investigate and fix this bug: ", Icon: Bug },
  { label: "Plan a feature", detail: "Make the next change clear", prompt: "Help me plan and implement this feature: ", Icon: ListChecks },
]
export function homeSubmission(prompt: string, model: string, privateSession: boolean, attachments: string[], selected: string[], available: HomeConnection[], securityProfileId = "", profiles: readonly string[] = []) {
  const connections = [...new Set(selected)].sort()
  const allowed = new Set(available.filter(row => row.enabled && (privateSession || row.shared)).map(row => row.id))
  if (connections.some(id => !allowed.has(id))) throw new Error("Account access changed. Review the selected accounts before sending.")
  if (securityProfileId && (!/^[0-9a-f]{32}$/.test(securityProfileId) || !profiles.includes(securityProfileId))) throw new Error("This security policy is no longer available. Choose another policy.")
  const body = { prompt, model, attachments, connections }, visibility: NonNullable<NewSession["visibility"]> = privateSession ? "private" : "shared"
  // An empty selection leaves the organization default to the server.
  const session: NewSession = { model, visibility, ...(securityProfileId ? { security_profile_id: securityProfileId } : {}) }
  return { body, visibility, session, signature: JSON.stringify([visibility, body, securityProfileId]) }
}

export function Home({ models, defaultModel, initiallyPrivate = false, individual = true, productMode = "standalone", connectionVersion = "", preferences, securityPolicies = false, spendStatus = false, recentSessions, recentLoading, onSearchSessions, onCreated, onStarted }: {
  models: string[]; defaultModel: string; initiallyPrivate?: boolean; individual?: boolean; productMode?: "standalone" | "existing"; connectionVersion?: string; preferences?: GeneralPreferences; securityPolicies?: boolean
  /** Show the personal monthly budget notice (existing product mode with spend.personal). */
  spendStatus?: boolean
  recentSessions: { key: string; title: Session["title"]; href: string }[]; recentLoading: boolean; onSearchSessions: () => void
  onCreated: () => Promise<void>; onStarted: (conversation: NewConversation) => void
}) {
  const [draft, setDraft] = useState("")
  const [model, setModel] = useState(defaultModel)
  const [privateSession, setPrivateSession] = useState(initiallyPrivate)
  const isPrivate = individual && privateSession
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [goalMode, setGoalMode] = useState(false)
  const pictures = useAttachments(setError)
  const fileDrop = useFileDrop(pictures.add, setError, busy)
  const [accountsVersion, setAccountsVersion] = useState(0)
  const [skippedScope, setSkippedScope] = useState("")
  const [catalog, setCatalog] = useState<{ scope: string; rows: HomeConnection[]; loading: boolean; error: string }>({ scope: "", rows: [], loading: false, error: "" })
  const [policies, setPolicies] = useState<SessionProfileCatalog | null>(null), [policyId, setPolicyId] = useState("")
  const policyNow = useRef(policyId)
  policyNow.current = policyId
  // The policy a new session would bind. A failed read leaves every choice to admission.
  // A refused send reads it again (policyRevision); the previous answer stays on screen meanwhile.
  const governed = productMode === "existing"
  const [policyRevision, setPolicyRevision] = useState(0)
  const [bound, setBound] = useState<{ profile: string; value: NewSessionSecurityPolicy | null; loading: boolean }>({ profile: "", value: null, loading: true })
  const boundPolicy = bound.profile === policyId ? bound.value : null
  const policyReady = !governed || (bound.profile === policyId && !bound.loading)
  const modelChoices = policyModels(models, boundPolicy?.policy)
  const sendModel = policyModel(models, boundPolicy?.policy, model, boundPolicy?.default_model)
  const noModel = policyReady && !sendModel
  const accountScope = `${isPrivate ? "private" : "shared"}:${connectionVersion}:${accountsVersion}`
  const catalogRows = catalog.scope === accountScope ? catalog.rows : []
  const accounts = catalogRows.filter(row => policyAdmitsConnection(boundPolicy?.policy, row))
  const skipAccounts = skippedScope === accountScope
  const needsAccounts = preferences?.connection_ids != null ? preferences.connection_ids.length > 0 : productMode === "existing"
  const preferred = (row: HomeConnection) => preferences?.connection_ids == null || preferences.connection_ids.includes(row.id)
  const selectedAccounts = skipAccounts || !needsAccounts ? [] : accounts.filter(preferred).map(row => row.id)
  const excludedAccounts = skipAccounts || !needsAccounts ? 0 : catalogRows.filter(preferred).length - accounts.filter(preferred).length
  const accountsReady = !needsAccounts || skipAccounts || (catalog.scope === accountScope && !catalog.loading && !catalog.error)
  const [composerFocus, setComposerFocus] = useState(0)
  const admission = useRef<{ signature: string; session?: Session; request: string } | null>(null)
  const submitting = useRef(false)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    document.title = "New session · Moyai"
    return () => { mounted.current = false }
  }, [])
  useEffect(() => {
    if (!needsAccounts) return
    const controller = new AbortController(), scope = accountScope
    setCatalog({ scope, rows: [], loading: true, error: "" })
    void listConnections({ query: { shared: !isPrivate }, signal: controller.signal }).then(({ data: rows }) => {
      if (controller.signal.aborted) return
      const eligible = rows.filter(row => row.enabled && (isPrivate || row.shared))
      setCatalog({ scope, rows: eligible, loading: false, error: "" })
    }, reason => { if (!controller.signal.aborted) setCatalog({ scope, rows: [], loading: false, error: String(reason) }) })
    return () => controller.abort()
  }, [needsAccounts, accountScope, isPrivate])

  async function send(prompt = draft) {
    if (prompt.trim() === "/goal") { setGoalMode(true); setDraft(""); setComposerFocus(value => value + 1); return }
    if (goalMode && !prompt.trim()) return
    if (noModel) return  // The alert above already explains why nothing is sent.
    const auth = csrfToken()
    try { await submit(goalMode ? `/goal --budget none ${prompt}` : prompt) }
    catch (reason) { if (mounted.current && csrfToken() === auth) setError(String(reason)) }
  }

  useEffect(() => {
    const unavailable = () => { setPolicies(null); setPolicyId("") }
    if (!securityPolicies) { unavailable(); return }
    const controller = new AbortController()
    // Without a catalog the server applies the organization default, so a failed
    // read hides the selector and clears the choice instead of blocking the session.
    void listSecurityProfileOptions({ signal: controller.signal }).then(({ data: value }) => {
      if (controller.signal.aborted) return
      setPolicies(value)
      if (policyNow.current && !value.profiles.some(profile => profile.id === policyNow.current)) {
        setPolicyId("")
      }
    }, () => { if (!controller.signal.aborted) unavailable() })
    return () => controller.abort()
  }, [securityPolicies])

  useEffect(() => {
    if (!governed) return
    const controller = new AbortController(), profile = policyId
    setBound(previous => ({ profile, value: previous.profile === profile ? previous.value : null, loading: true }))
    void getNewSessionSecurityPolicy({ query: profile ? { profile_id: profile } : {}, signal: controller.signal }).then(({ data: value }) => {
      if (!controller.signal.aborted) setBound({ profile, value, loading: false })
    }, () => { if (!controller.signal.aborted) setBound({ profile, value: null, loading: false }) })
    return () => controller.abort()
  }, [governed, policyId, policyRevision])

  async function submit(prompt: string): Promise<void> {
    const action = goalCommandAction(prompt)
    if (action && action !== "set") throw new Error("Open an existing conversation to change its goal.")
    if (submitting.current) throw new Error("A message is already being sent.")
    if (pictures.uploading) throw new Error("Wait for the attached files to finish uploading, then retry.")
    if (pictures.hasErrors) throw new Error("Retry or remove the failed attachments before sending.")
    if (!accountsReady) throw new Error(catalog.error
      ? "Connections could not be loaded. Cancel to retry connections or continue without them."
      : "Connections are still loading. Retry when they are ready.")
    if (!policyReady) throw new Error("The security policy is still loading. Retry when it is ready.")
    if (!prompt.trim() && !pictures.files.length) throw new Error("Enter a message or attach a file.")
    submitting.current = true
    setBusy(true); setError("")
    const auth = csrfToken(), attachments = pictures.readyFiles
    const requireCurrent = () => {
      if (!mounted.current || csrfToken() !== auth) throw new Error("Your sign-in changed. Retry from the current workspace.")
    }
    try {
      const submission = homeSubmission(prompt, sendModel, isPrivate, attachments.map(file => file.id), selectedAccounts, accounts, policyId, policies?.profiles.map(profile => profile.id))
      const signature = JSON.stringify([auth, submission.signature])
      if (admission.current?.signature !== signature) admission.current = { signature, request: crypto.randomUUID() }
      const attempt = admission.current
      if (!attempt.session) {
        attempt.session = (await createSession({ body: submission.session })).data
      }
      requireCurrent()
      const { data: turn } = await createSessionMessage({ path: { session_id: attempt.session.id }, body: {
        ...submission.body, request_key: attempt.request,
      } })
      requireCurrent()
      if (!("id" in turn)) throw new Error("The request did not start a conversation.")
      onStarted({ session: attempt.session, turn, prompt, attachments })
      // Admission succeeded. A list refresh failure must not invite a second start.
      try { await onCreated() }
      catch { if (mounted.current && csrfToken() === auth) setError("Your message was sent, but the session list could not be refreshed.") }
    }
    catch (reason) {
      // An administrator may have narrowed the policy since it was read; offer its current choices before a retry.
      if (reason instanceof ApiError && reason.status === 403 && mounted.current) setPolicyRevision(value => value + 1)
      throw reason
    }
    finally { submitting.current = false; if (mounted.current) setBusy(false) }
  }

  const defaultPolicy = policies?.profiles.find(profile => profile.id === policies.default_profile_id)
  return <section className="home file-drop-zone" {...fileDrop.handlers}>
    {fileDrop.dragging && <FileDropOverlay />}
    <SpaceBackdrop />
    <div className="home-content">
      <header className="home-header">
        <h1>What are we <span>building?</span></h1>
      </header>
      <form className="home-form" onSubmit={event => { event.preventDefault(); void send() }}>
        {error && <p className="error" role="alert">{error}</p>}
        {noModel && <p className="error" role="alert">This security policy allows no models. Choose another policy or ask an administrator.</p>}
        {spendStatus && <SpendStatusNotice />}
        {needsAccounts && catalog.scope === accountScope && catalog.error && !skipAccounts && <div className="home-connection-error" role="alert">
          <span className="error">{catalog.error}</span>
          <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => setAccountsVersion(value => value + 1)}>Retry connections</Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setSkippedScope(accountScope)}>Continue without connections</Button>
        </div>}
        <div className="composer home-composer">
          <AttachmentPreviews files={pictures.files} remove={busy ? undefined : pictures.remove} retry={busy ? undefined : pictures.retry} draft />
          <div className="home-editor-input"><SkillComposer focusRequest={composerFocus} value={draft} onChange={setDraft} onSend={prompt => void send(prompt)} onGoalSelect={() => { setGoalMode(true); setDraft("") }} shared={!isPrivate} disabled={busy} placeholder={goalMode ? "Describe a goal to keep pursuing…" : "Describe a change, paste an error, or ask a question…"} onPaste={pictures.paste} /></div>
          <div className="composer-actions">
            <div className="home-composer-tools">
              <AttachButton add={pictures.add} disabled={busy} compact />
              <Button type="button" variant="ghost" size="sm" className="home-privacy-toggle" aria-label="Private session" aria-pressed={isPrivate} disabled={!individual || busy}
                title={!individual ? "Private sessions require an individual sign-in." : isPrivate ? "Private · Only you. Click to share with your workspace." : "Public · Shared with your workspace. Click to make private."}
                onClick={() => { setSkippedScope(""); setPrivateSession(value => !value) }}>
                {isPrivate ? <LockKeyhole /> : <Globe />}{isPrivate ? "Private" : "Public"}
              </Button>
              {goalMode && <GoalChip disabled={busy} onRemove={() => { setGoalMode(false); setComposerFocus(value => value + 1) }} />}
            </div>
            <div className="send-actions"><Select value={sendModel} onValueChange={setModel} disabled={noModel}><SelectTrigger aria-label="Model"><SelectValue placeholder="No allowed models" /></SelectTrigger><SelectContent>{modelChoices.map(value => <SelectItem value={value} key={value}>{value.replace(/^openai\//, "")}</SelectItem>)}</SelectContent></Select>
              <Button type="submit" size="icon" aria-label="Send message" disabled={busy || pictures.uploading || pictures.hasErrors || !accountsReady || !policyReady || noModel || (!draft.trim() && (goalMode || !pictures.files.length))}><Send /></Button>
            </div>
          </div>
        </div>
        <div className="home-composer-hint">
          {busy && <span role="status">Sending…</span>}
          {pictures.uploading && <span role="status">Uploading files…</span>}
          {needsAccounts && !accountsReady && !catalog.error && <span role="status">Loading connections…</span>}
          {!policyReady && <span role="status">Loading security policy…</span>}
          {accountsReady && excludedAccounts > 0 && <span role="status">{excludedAccounts === 1 ? "1 connection is" : `${excludedAccounts} connections are`} not allowed by this security policy</span>}
          <span>Drop files or paste images · Enter to send</span>
        </div>

        {policies && <div className="home-policy"><label htmlFor="home-security-policy">Security policy</label><Select value={policyId || "__default__"} disabled={busy} onValueChange={value => setPolicyId(value === "__default__" ? "" : value)}><SelectTrigger id="home-security-policy" aria-label="Security policy"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__default__">Organization default{defaultPolicy ? ` · ${defaultPolicy.name}` : ""}</SelectItem>{policies.profiles.map(profile => <SelectItem value={profile.id} key={profile.id}>{profile.name}</SelectItem>)}</SelectContent></Select></div>}
      </form>
      <section className="home-recent" aria-labelledby="home-recent-heading">
        <div className="home-recent-header">
          <h2 id="home-recent-heading">Recent sessions</h2>
          <Button type="button" variant="ghost" size="sm" onClick={onSearchSessions}><Search aria-hidden="true" />Search sessions</Button>
        </div>
        {recentSessions.length > 0 ? <ul>
          {recentSessions.map(row => <li key={row.key}><Button asChild variant="ghost" className="home-recent-link">
            <a href={row.href} title={row.title || "Untitled session"}><Clock3 aria-hidden="true" /><span>{row.title || "Untitled session"}</span><ArrowUpRight aria-hidden="true" /></a>
          </Button></li>)}
        </ul> : <p className="muted" role="status">{recentLoading ? "Loading recent sessions…" : "No recent sessions in this view. Search to find more."}</p>}
      </section>
      <div className="home-starters" role="group" aria-label="Start with a prompt" aria-hidden={Boolean(draft.trim())}>
        <p className="home-starters-heading">Start with a prompt</p>
        {starters.map(({ label, detail, prompt, Icon }) => <Button key={label} type="button" variant="ghost" aria-label={label} disabled={busy || Boolean(draft.trim())}
          onClick={() => {
            setDraft(prompt)
            setComposerFocus(value => value + 1)
          }}><Icon aria-hidden="true" /><span className="home-starter-label">{label}</span><span className="home-starter-detail" aria-hidden="true">{detail}</span><ArrowUpRight className="home-starter-arrow" aria-hidden="true" /></Button>)}
      </div>
    </div>
  </section>
}
