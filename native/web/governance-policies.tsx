import { useId, useState } from "react"
import { Pencil, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { Choice, Empty, Toolbar, contains, dateTime } from "./settings"
import { defaultsBody, networkHint, policyBody, policyDraft, policySummary, repositoryLabel, type PolicyDraft, type ScopeMode } from "./governance-data"
import { DialogActions, GovConfirm, GovDialog, LoadGate, MutationError, PageActions, Section, StatusBadge, dataOf, useGovMutation, useGovResource } from "./governance-shared"
import {
  createSecurityProfile, disableSecurityProfile, listSecurityProfiles, updateSecurityProfile, updateSecurityProfileDefaults,
  type PolicyCatalog as Catalog, type SecurityProfileDefaults as ProfileDefaults, type SecurityProfileView as SecurityProfile, type SecurityProfilesAdmin,
} from "./generated/api"
import type { ConnectedApp, GitAccess } from "./governance-types"

const NONE = "__none__"
const toggled = <T,>(list: readonly T[], value: T, checked: boolean): T[] => checked ? [...new Set([...list, value])] : list.filter(item => item !== value)

export function ProfileRows({ profiles, defaults, catalog, onEdit, onDisable, onEnable }: {
  profiles: SecurityProfile[]; defaults: ProfileDefaults; catalog: Catalog
  onEdit: (profile: SecurityProfile) => void; onDisable: (profile: SecurityProfile) => void; onEnable: (profile: SecurityProfile) => void
}) {
  const labels = {
    app: (id: string) => catalog.connected_apps.find(app => app.id === id)?.label || id,
    repository: (id: number) => repositoryLabel(catalog.repositories, id),
    model: (id: string) => catalog.models.find(model => model.id === id)?.label || id,
  }
  return <div className="ns-records">{profiles.map(profile => {
    const summary = policySummary(profile.policy, labels)
    const isDefault = defaults.default_profile_id === profile.id, mandatory = defaults.mandatory_profile_id === profile.id
    return <article className="ns-record" key={profile.id}><div className="ns-record-copy">
      <div className="ns-record-title"><h3>{profile.name}</h3>
        {isDefault && <StatusBadge tone="neutral">Default</StatusBadge>}{mandatory && <StatusBadge tone="warning">Mandatory</StatusBadge>}
        {!profile.enabled && <StatusBadge tone="neutral">Disabled</StatusBadge>}</div>
      <dl className="ns-gov-summary">
        <div><dt>Connected apps</dt><dd>{summary.apps}</dd></div><div><dt>Tools</dt><dd>{summary.tools}</dd></div>
        <div><dt>Git access</dt><dd>{summary.git}</dd></div><div><dt>Network</dt><dd>{summary.network}</dd></div>
        <div><dt>Repositories</dt><dd>{summary.repositories}</dd></div><div><dt>Models</dt><dd>{summary.models}</dd></div>
      </dl>
      <small>Revision {profile.revision} · Updated {dateTime(profile.updated_at)}{profile.updated_by ? ` by ${profile.updated_by}` : ""}</small>
      {profile.enabled && (isDefault || mandatory) && <small>Change the organization defaults before disabling this policy.</small>}
    </div><div className="ns-row-actions">
      <Button variant="outline" size="sm" onClick={() => onEdit(profile)}><Pencil />Edit<span className="visually-hidden"> {profile.name}</span></Button>
      {profile.enabled ? !isDefault && !mandatory && <Button variant="ghost" size="sm" onClick={() => onDisable(profile)}>Disable<span className="visually-hidden"> {profile.name}</span></Button>
        : <Button variant="ghost" size="sm" onClick={() => onEnable(profile)}>Enable<span className="visually-hidden"> {profile.name}</span></Button>}
    </div></article>
  })}</div>
}

export function SecurityPoliciesPage() {
  const resource = useGovResource("security-profiles", signal => listSecurityProfiles({ signal }).then(dataOf))
  const [search, setSearch] = useState(""), [status, setStatus] = useState("all")
  const [editor, setEditor] = useState<SecurityProfile | "new" | null>(null), [disable, setDisable] = useState<SecurityProfile | null>(null)
  const toggle = useGovMutation()
  return <LoadGate resource={resource} label="security policies">{data => {
    const rows = data.profiles.filter(profile => contains(search, profile.name, ...(profile.policy.network_domains ?? []), ...(profile.policy.tools ?? []),
      ...(profile.policy.repositories ?? []).map(id => repositoryLabel(data.catalog.repositories, id)), ...(profile.policy.models ?? []))
      && (status === "all" || (status === "enabled") === profile.enabled))
    return <>
      <div className="ns-gov-intro"><p className="ns-notice">Each setting allows everything, allows only what you list, or allows nothing. A session uses the policy chosen when it starts; the mandatory policy then applies on top, and the stricter setting wins.</p>
        <PageActions resource={resource} /></div>
      <Section id="gov-defaults" title="Organization defaults" description="The default applies to new sessions unless someone who can manage security policies chooses another. The mandatory policy always applies, including to automations and delegated agents.">
        <DefaultsForm admin={data} onSaved={resource.refresh} />
      </Section>
      <Section id="gov-profiles" title="Policies" action={<Button onClick={() => setEditor("new")}><Plus />New policy</Button>}>
        <Toolbar search={search} setSearch={setSearch} count={rows.length} label="Search policies"
          filter={<Choice label="Policy status" value={status} onChange={setStatus} options={[{ value: "all", label: "All policies" }, { value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }]} />} />
        <MutationError mutation={toggle} onReload={resource.refresh} />
        {rows.length ? <ProfileRows profiles={rows} defaults={data.defaults} catalog={data.catalog} onEdit={setEditor} onDisable={setDisable}
          onEnable={profile => void toggle.run(() => updateSecurityProfile({ path: { identity: profile.id }, body: { name: profile.name, enabled: true, policy: profile.policy, revision: profile.revision } }), resource.refresh)} />
          : data.profiles.length ? <Empty filtered noun="policies" onClear={() => { setSearch(""); setStatus("all") }} />
            : <div className="ns-empty"><h3>No security policies yet</h3><p>Sessions are unrestricted until you create a policy and choose it as the default or mandatory policy.</p></div>}
      </Section>
      {editor && <PolicyEditor profile={editor === "new" ? undefined : editor} catalog={data.catalog} defaults={data.defaults} onClose={() => setEditor(null)} onSaved={resource.refresh} />}
      {disable && <GovConfirm title={`Disable ${disable.name}?`} label="Disable policy" onReload={resource.refresh} onClose={() => setDisable(null)}
        description="People can no longer choose it for new sessions. Sessions that already started with it keep their recorded policy. You can enable it again later."
        onConfirm={async () => { await disableSecurityProfile({ path: { identity: disable.id }, query: { revision: disable.revision } }); resource.refresh() }} />}
    </>
  }}</LoadGate>
}

function DefaultsForm({ admin, onSaved }: { admin: SecurityProfilesAdmin; onSaved: () => void }) {
  const mutation = useGovMutation(), id = useId()
  const [defaultId, setDefaultId] = useState(admin.defaults.default_profile_id || NONE)
  const [mandatoryId, setMandatoryId] = useState(admin.defaults.mandatory_profile_id || NONE)
  const [saved, setSaved] = useState(false), [revision, setRevision] = useState(admin.defaults.revision)
  // A new server revision replaces the draft; a refresh at the same revision keeps it.
  if (revision !== admin.defaults.revision) {
    setRevision(admin.defaults.revision); setDefaultId(admin.defaults.default_profile_id || NONE); setMandatoryId(admin.defaults.mandatory_profile_id || NONE)
  }
  const enabled = admin.profiles.filter(profile => profile.enabled)
  const options = (current: string, none: string) => [{ value: NONE, label: none }, ...admin.profiles.filter(profile => profile.enabled || profile.id === current)
    .map(profile => ({ value: profile.id, label: profile.enabled ? profile.name : `${profile.name} (disabled)` }))]
  const value = (choice: string) => choice === NONE ? "" : choice
  const dirty = value(defaultId) !== admin.defaults.default_profile_id || value(mandatoryId) !== admin.defaults.mandatory_profile_id
  if (!admin.profiles.length) return <p className="ns-muted">Create a policy below to choose organization defaults.</p>
  return <form className="ns-gov-defaults" onSubmit={event => { event.preventDefault(); setSaved(false)
    void mutation.run(async () => { await updateSecurityProfileDefaults({ body: defaultsBody(value(defaultId), value(mandatoryId), admin.defaults.revision, admin.profiles) }) }, () => { setSaved(true); onSaved() }) }}>
    <div className="ns-gov-field-pair">
      <div className="ns-field"><label htmlFor={`${id}-default`}>Default for new sessions</label><Choice id={`${id}-default`} label="Default for new sessions" value={defaultId} disabled={mutation.busy} onChange={next => { setDefaultId(next); setSaved(false) }} options={options(admin.defaults.default_profile_id, "No default (unrestricted)")} />
        <p className="ns-field-hint">New sessions use this policy. Only people with the Manage security policies permission can choose another enabled policy when they start a session or set up a workflow.</p></div>
      <div className="ns-field"><label htmlFor={`${id}-mandatory`}>Mandatory policy</label><Choice id={`${id}-mandatory`} label="Mandatory policy" value={mandatoryId} disabled={mutation.busy} onChange={next => { setMandatoryId(next); setSaved(false) }} options={options(admin.defaults.mandatory_profile_id, "No mandatory policy")} />
        <p className="ns-field-hint">Changes also apply to work that is already running.</p></div>
    </div>
    {!enabled.length && <p className="ns-muted">Enable a policy to use it as a default.</p>}
    <MutationError mutation={mutation} onReload={onSaved} />
    <div className="ns-row-actions"><Button type="submit" variant="outline" disabled={mutation.busy || !dirty}>{mutation.busy ? "Saving…" : "Save defaults"}</Button>
      <span className="ns-muted" role="status">{saved ? "Defaults saved." : dirty ? "Unsaved changes." : admin.defaults.updated_at ? `Last changed ${dateTime(admin.defaults.updated_at)}${admin.defaults.updated_by ? ` by ${admin.defaults.updated_by}` : ""}.` : ""}</span></div>
  </form>
}

function ScopeChoice({ id, label, value, onChange, disabled, all, selected, none }: { id: string; label: string; value: ScopeMode; onChange: (value: ScopeMode) => void; disabled: boolean; all: string; selected: string; none: string }) {
  return <Choice id={id} label={label} value={value} disabled={disabled} onChange={next => onChange(next as ScopeMode)}
    options={[{ value: "all", label: all }, { value: "selected", label: selected }, { value: "none", label: none }]} />
}

type PickItem<T> = { id: T; label: string; group: string }
/** A filterable, grouped checkbox list; each item shows its ID under its label. */
function PickList<T extends string | number>({ id, noun, items, selected, disabled, onPick }: {
  id: string; noun: string; items: readonly PickItem<T>[]; selected: readonly T[]; disabled: boolean; onPick: (value: T, checked: boolean) => void
}) {
  const [filter, setFilter] = useState("")
  const visible = items.filter(item => contains(filter, String(item.id), item.label, item.group))
  const groups = [...new Set(visible.map(item => item.group || "Other"))]
  return <>
    <div className="ns-field"><label htmlFor={`${id}-filter`}>Filter {noun}</label><Input id={`${id}-filter`} type="search" value={filter} onChange={event => setFilter(event.target.value)} /></div>
    <div className="ns-gov-tool-list" role="group" aria-label={`Allowed ${noun}, ${selected.length} selected`} tabIndex={0}>
      {groups.map(group => <fieldset key={group}><legend>{group}</legend>{visible.filter(item => (item.group || "Other") === group).map(item => <div className="ns-gov-check" key={item.id}>
        <Checkbox id={`${id}-${item.id}`} checked={selected.includes(item.id)} disabled={disabled} aria-describedby={`${id}-${item.id}-name`} onCheckedChange={checked => onPick(item.id, checked === true)} />
        <div><label htmlFor={`${id}-${item.id}`}>{item.label}</label><small id={`${id}-${item.id}-name`}><code>{item.id}</code></small></div></div>)}</fieldset>)}
      {!visible.length && <p className="ns-muted">No {noun} match this filter.</p>}
    </div>
    <p className="ns-field-hint">{selected.length} selected.</p>
  </>
}
/** Catalog entries, then saved entries the catalog no longer offers, so an edit never silently drops them. */
function withSaved<T extends string | number>(catalog: readonly PickItem<T>[], saved: readonly T[], label: (id: T) => string): PickItem<T>[] {
  const known = new Set(catalog.map(item => item.id))
  return [...catalog, ...saved.filter(value => !known.has(value)).map(value => ({ id: value, label: label(value), group: "Saved, not in the current catalog" }))]
}

export function PolicyEditor({ profile, catalog, defaults, onClose, onSaved }: {
  profile?: SecurityProfile; catalog: Catalog; defaults: ProfileDefaults; onClose: () => void; onSaved: () => void
}) {
  const mutation = useGovMutation(), id = useId()
  const [draft, setDraft] = useState<PolicyDraft>(() => policyDraft(profile))
  const change = (patch: Partial<PolicyDraft>) => setDraft(previous => ({ ...previous, ...patch }))
  const pickApp = (app: ConnectedApp, checked: boolean) => setDraft(previous => ({ ...previous, app_ids: toggled(previous.app_ids, app, checked) }))
  const pickTool = (tool: string, checked: boolean) => setDraft(previous => ({ ...previous, tool_ids: toggled(previous.tool_ids, tool, checked) }))
  const pickRepository = (repository: number, checked: boolean) => setDraft(previous => ({ ...previous, repository_ids: toggled(previous.repository_ids, repository, checked) }))
  const pickModel = (model: string, checked: boolean) => setDraft(previous => ({ ...previous, model_ids: toggled(previous.model_ids, model, checked) }))
  const inUse = Boolean(profile && (defaults.default_profile_id === profile.id || defaults.mandatory_profile_id === profile.id))
  const tools = withSaved(catalog.tools, draft.tool_ids, tool => tool)
  const repositories = withSaved(catalog.repositories.map(repository => ({ ...repository, group: "GitHub repositories" })), draft.repository_ids, repository => repositoryLabel(catalog.repositories, repository))
  const models = withSaved(catalog.models.map(model => ({ ...model, group: "Workspace models" })), draft.model_ids, model => model)
  return <GovDialog wide title={profile ? `Edit ${profile.name}` : "New security policy"} busy={mutation.busy} onClose={onClose}
    description="Saving creates a new revision. Sessions that already started keep the revision they started with.">
    <form className="ns-fields" onSubmit={event => { event.preventDefault(); void mutation.run(async () => {
      const body = policyBody(draft, profile)
      if (profile) await updateSecurityProfile({ path: { identity: profile.id }, body })
      else await createSecurityProfile({ body })
    }, () => { onSaved(); onClose() }) }}>
      <div className="ns-field"><label htmlFor={`${id}-name`}>Policy name</label><Input id={`${id}-name`} autoFocus required maxLength={80} disabled={mutation.busy} value={draft.name} onChange={event => change({ name: event.target.value })} /></div>
      <div className="ns-gov-check"><Checkbox id={`${id}-enabled`} checked={draft.enabled} disabled={mutation.busy || inUse} onCheckedChange={value => change({ enabled: value === true })} aria-describedby={`${id}-enabled-hint`} />
        <div><label htmlFor={`${id}-enabled`}>Available for new sessions</label><small id={`${id}-enabled-hint`}>{inUse ? "This policy is an organization default, so it stays enabled." : "Disabled policies cannot be chosen for new sessions."}</small></div></div>

      <fieldset className="ns-gov-policy-block"><legend>Connected apps</legend>
        <div className="ns-field"><label htmlFor={`${id}-apps`}>Which connected apps can sessions use?</label>
          <ScopeChoice id={`${id}-apps`} label="Connected apps" value={draft.apps} disabled={mutation.busy} onChange={apps => change({ apps })} all="All connected apps" selected="Only selected apps" none="No connected apps" />
          <p className="ns-field-hint">{draft.apps === "all" ? "Sessions can use any app connection the person can already use." : draft.apps === "none" ? "Sessions cannot use GitHub, Linear, Slack or Notion connections." : "Sessions can use only the apps checked below."}</p></div>
        {draft.apps === "selected" && <div className="ns-gov-options" role="group" aria-label="Allowed connected apps">{catalog.connected_apps.map(app => <div className="ns-gov-check" key={app.id}>
          <Checkbox id={`${id}-app-${app.id}`} checked={draft.app_ids.includes(app.id)} disabled={mutation.busy} onCheckedChange={checked => pickApp(app.id, checked === true)} /><div><label htmlFor={`${id}-app-${app.id}`}>{app.label}</label></div></div>)}</div>}
      </fieldset>

      <fieldset className="ns-gov-policy-block"><legend>Agent tools</legend>
        <div className="ns-field"><label htmlFor={`${id}-tools`}>Which tools can the agent call?</label>
          <ScopeChoice id={`${id}-tools`} label="Agent tools" value={draft.tools} disabled={mutation.busy} onChange={tools => change({ tools })} all="All tools" selected="Only selected tools" none="No tools" />
          <p className="ns-field-hint">{draft.tools === "all" ? "Every tool the person’s role allows stays available." : draft.tools === "none" ? "No tools are offered to the agent, including commands, file edits and app actions. It can only reply in chat." : "Only the checked tools are offered to the agent. Role permissions still apply."}</p></div>
        {draft.tools === "selected" && <PickList id={`${id}-tool`} noun="tools" items={tools} selected={draft.tool_ids} disabled={mutation.busy} onPick={pickTool} />}
      </fieldset>

      <fieldset className="ns-gov-policy-block"><legend>Git access</legend>
        <div className="ns-field"><label htmlFor={`${id}-git`}>What can sessions do with GitHub repositories?</label>
          <Choice id={`${id}-git`} label="Git access" value={draft.git_access} disabled={mutation.busy} onChange={git_access => change({ git_access: git_access as GitAccess })}
            options={[{ value: "write", label: "Read and write" }, { value: "read", label: "Read only" }, { value: "none", label: "No Git access" }]} />
          <p className="ns-field-hint">{draft.git_access === "write" ? "Sessions can open and update pull requests when the person is allowed to." : draft.git_access === "read" ? "Sessions can read repositories but cannot push, publish or open pull requests." : "GitHub tools are removed from sessions."}</p></div>
      </fieldset>

      <fieldset className="ns-gov-policy-block"><legend>Repositories</legend>
        <div className="ns-field"><label htmlFor={`${id}-repositories`}>Which GitHub repositories can sessions use?</label>
          <ScopeChoice id={`${id}-repositories`} label="Repositories" value={draft.repositories} disabled={mutation.busy} onChange={repositories => change({ repositories })} all="All repositories" selected="Only selected repositories" none="No repositories" />
          <p className="ns-field-hint">{draft.repositories === "all" ? "Sessions can use any repository the GitHub connection and Git access allow." : draft.repositories === "none" ? "Sessions cannot use any GitHub repository, including public ones." : "Sessions can use only the checked repositories. Every other repository is refused, including public ones and environments built from them."}</p></div>
        {draft.repositories === "selected" && <PickList id={`${id}-repository`} noun="repositories" items={repositories} selected={draft.repository_ids} disabled={mutation.busy} onPick={pickRepository} />}
      </fieldset>

      <fieldset className="ns-gov-policy-block"><legend>Models</legend>
        <div className="ns-field"><label htmlFor={`${id}-models`}>Which models can sessions use?</label>
          <ScopeChoice id={`${id}-models`} label="Models" value={draft.models} disabled={mutation.busy} onChange={models => change({ models })} all="All models" selected="Only selected models" none="No models" />
          <p className="ns-field-hint">{draft.models === "all" ? "Sessions can use every model enabled for this workspace." : draft.models === "none" ? "No model is allowed, so sessions under this policy cannot start or continue." : "Sessions and workflows can use only the checked models. New sessions start on the first allowed model when the default is not checked."}</p></div>
        {draft.models === "selected" && <PickList id={`${id}-model`} noun="models" items={models} selected={draft.model_ids} disabled={mutation.busy} onPick={pickModel} />}
      </fieldset>

      <fieldset className="ns-gov-policy-block"><legend>Network access</legend>
        <div className="ns-field"><label htmlFor={`${id}-network`}>Where can the session’s cloud machine connect?</label>
          <Choice id={`${id}-network`} label="Network access" value={draft.network} disabled={mutation.busy} onChange={network => change({ network: network as PolicyDraft["network"] })}
            options={[{ value: "all", label: "Unrestricted" }, { value: "listed", label: "Only listed domains" }, { value: "none", label: "Block all outbound network access" }]} />
          <p className="ns-field-hint">{networkHint(draft.network, catalog.network_enforcement)}</p></div>
        {draft.network === "listed" && <div className="ns-field"><label htmlFor={`${id}-domains`}>Allowed domains</label>
          <Textarea id={`${id}-domains`} className="ns-gov-short" rows={4} disabled={mutation.busy} value={draft.domains} spellCheck={false} placeholder={"registry.npmjs.org\n*.githubusercontent.com"} aria-describedby={`${id}-domains-hint`} onChange={event => change({ domains: event.target.value })} />
          <p id={`${id}-domains-hint`} className="ns-field-hint">One hostname per line. Use *.example.com to include its subdomains. No URLs, ports or IP addresses; up to 200 entries.</p></div>}
      </fieldset>
      <MutationError mutation={mutation} onReload={() => { onSaved(); onClose() }} />
      <DialogActions busy={mutation.busy} onCancel={onClose} submitLabel={profile ? "Save policy" : "Create policy"} />
    </form>
  </GovDialog>
}
