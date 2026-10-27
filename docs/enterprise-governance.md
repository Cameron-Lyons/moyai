# Enterprise governance

Governance is enforced by the native Pydantic runtime in existing-product mode
(`MOYAI_PRODUCT_MODE=existing`). Settings includes Roles & access, Provisioning,
Security policies, Spend limits, and Audit log. The retired execution engine is
not required.

## Deployment and migration

Apply canonical schema revision **25** and native application migration
**2026-10-21-product-governance-v24** during the coordinated maintenance window
in [the deployment contract](pydantic-deployment.md). Canonical revision 25 combines
upstream revision 22 with the governance branch's older revision 22, plus the
role permissions revision added after the first combined revision 23 (revision 24)
and the service account, activity audit and spend tier tables (revision 25); none
of the older layouts is admitted as the combined release. Revision 25 raises the
compatibility floor, so revision 24 services must not overlap it: they would
ignore spend tiers. Rolling back to them needs the reviewed database restore
procedure. Revision 25 needs no native migration of its own. The v24 native
migration follows upstream v23 (automation chats), adds an immutable
session-policy table and preserves the previous 23 migration receipts. It is also a registered
[online expansion](native-online-schema.md), so the native table can be prepared
while v23 services run; the canonical revision still needs the maintenance
window. Normal startup verifies both schemas; it does not run migrations.

The canonical upgrade retains existing governance configuration and audit events,
copies the older `floor_profile_id` into the mandatory policy, and adds SCIM
revocation epochs. Previously inactive directory users remain revoked. Revision 25
only adds empty tables: `service_accounts` and `service_account_keys`,
`governance_activity_events` (whose rows reject updates on both databases but can
be deleted), and `spend_group_limits`. Existing native sessions without policy
bindings have no selected profile, and are still subject to the current mandatory
policy. A continuation of a historical governed session intersects its saved
policy with the new native binding; an unreadable saved policy blocks the
continuation for review.

Repository and model limits need no schema change. A stored policy without them
keeps the four-key document the previous release wrote, byte for byte, so
existing profiles, revisions and immutable session bindings load unchanged. A
policy that uses either limit is stored with all six keys, which the previous
release refuses as invalid (it fails closed). Because this release raises the
compatibility floor, rolling back to the previous (revision 24) release means
restoring the pre-upgrade database backup, which has no repository or model
limits; clearing them from profiles is not a rollback step.

Use `MOYAI_ORGANIZATION_ID` for one organization per deployment and database.
The immutable database pin rejects a different organization at startup. An existing
populated database cannot acquire a new pin without a separate namespace migration.
Organization deployments require their own provisioned Temporal namespace. Source
resource names and native task queues/object prefixes are scoped idempotently to
the organization. This is deployment isolation, not request-selected multitenancy.
Scoping renames resources inside the configured accounts; separate cloud
credentials, buckets, and accounts remain the operator's responsibility.

## Roles and provisioning

Built-in administrators retain all catalog permissions. Internal users keep their
existing session, connection, workflow, personal-library, and personal-spend access.
A custom role replaces an internal user's default permissions; active SCIM group
grants add permissions by union. Assignments do not change sign-in eligibility or
make shared conversations private. Built-in roles cannot be edited or archived.

In existing-product mode, Slack senders need a verified in-domain Slack profile.
That requires `SLACK_IDENTITY_LINKING_ENABLED` (the default) and the `users:read`
and `users:read.email` Slack scopes. A verified sender never exceeds member access.
Senders who are unverified, or linked only manually, hold no permissions and are
refused; upstream admitted them as members. Deployments that disable identity
linking cannot verify new senders, so those senders are refused.

The server checks permissions independently of navigation visibility. Native
session and turn admission, tool catalogs, actual tool attempts and retries,
connection credentials, model dispatch, memory recall, and workspace preparation
resolve current authority. Role permission changes, archives, assignments, group
grants and SCIM revocations invalidate saved execution grants; renaming a role or
editing its description does not. Reactivation does not restore an earlier
revoked grant.

Only a built-in administrator can grant or remove administrator access. Delegated
role managers may grant only permissions they directly hold. Custom-role
replacement in Settings → Users requires an explicit revision-checked replacement.
The metadata audit records successful changes in the same transaction.

Provisioning uses `/scim/v2` with bearer credentials created in Settings →
Provisioning. Tokens are shown once and stored as hashes. The directory supports
Users, Groups, filtering, pagination, PATCH, deactivation, and retained tombstones.
SCIM does not create an interactive login session. Revoking a token stops that
provisioning credential without deleting the provisioned directory. With
Cloudflare Access sign-in, provisioning operations need only that bearer
credential, not an Access assertion; token administration still requires Access.
The edge must also let the identity provider reach `/scim/v2` (an Access bypass
or service-auth policy for that path), because the origin exemption cannot see
requests Access blocks. Directory writes take the canonical writer lock and
briefly pause native admissions, so run large initial imports or group
replacements off-peak.

People can also sign in through an organization OpenID Connect provider (Okta,
Microsoft Entra ID); see [sign-in](authentication.md#organization-openid-connect-okta-microsoft-entra-id).
Sign-in and every later request recheck SCIM state: a deactivated person is
refused, and a provider with `require_scim_user` accepts only active provisioned
people. Its group claims grant nothing; SCIM groups remain the source of group
grants.

| Permission | Governance access |
| --- | --- |
| `users.read` / `users.manage` | User directory / built-in role assignments |
| `roles.manage` | Custom roles, email assignments, group grants |
| `scim.manage` | Provisioning directory and token revocation; only built-in administrators create tokens |
| `security.manage` | Policy configuration and explicit profile selection |
| `spend.read` / `spend.manage` | Organization spend / limit configuration |
| `audit.read` | Audit feed and exports |
| `runtime.manage` | Performance reports, which include cost and so also require `spend.read` |

`GET /api/permissions` returns the full catalog and effective permissions.
Organization accounting and usage exports honor delegated `spend.read` access;
`spend.personal` controls personal reports. Limit managers without `spend.read`
receive configuration changes without usage totals. Reports recheck the original
live authority before releasing their results.

## Session policies

Policies constrain connected apps, tool names, managed Git access (`write`,
`read`, or `none`), network destinations, GitHub repositories, and models. For
apps, tools, domains, repositories, and models, `null` is unrestricted, an empty
list permits nothing, and a populated list is an allowlist. Intersections can
only narrow a bound policy. Git access `none` also refuses GitHub connections.
Slack has no account picker, so a Slack message selects only the connections its
session policy and the sender's role allow.

Repository limits list permanent GitHub repository IDs, not owner/name text, so
a rename or transfer cannot change what they allow. The editor offers the GitHub
App installation's repositories by their last known names; a saved repository
that later leaves the installation is shown as `Repository <id>` and stays in
the policy until removed. Only repositories the editor currently offers can be
added. A limit refuses every other repository, including public ones and
environments built from them, and a repository whose ID was never verified. It
is checked when GitHub connections are selected for a turn and on every later
tool or activity authorization, before any GitHub token is released, and before
repository checkout or environment use. A narrower mandatory limit therefore
also stops running sessions that use a repository it no longer lists.
Selecting the GitHub app for a workflow keeps only its policy's repositories.

Model limits list the workspace's model IDs exactly as Settings offers them;
GPT-6 Astra and GPT-6 Astra Ultrafast are separate entries. Every paid model
request is checked against the session's effective policy, including delegated
agents, swarms, goals, automations, Slack and memory review, whether or not a
spend limit is configured. A new session that does not ask for a model starts on
the workspace default when the policy allows it, otherwise on the first allowed
model; an explicitly requested model must be allowed. A policy that allows no
model stops all sessions under it.

Model and connection pickers follow the effective policy, but admission still
decides. Home reads the policy a new session would bind (with the chosen profile
and the mandatory policy) and offers only its models and the connections it
allows, starting on the model that session would get (a new side chat leaves
the model to that default as well); the conversation composer
does the same with its session's policy, so a narrower mandatory limit moves it
to an allowed model. Both wait for that read before sending, and Home reads the
policy again after a refused send. Continuing a historical conversation offers the
organization default's choices, which its saved policy can narrow further at
admission. The workflow editor checks its workflow's profile, and its readiness
review reports `repository_not_allowed_by_security_policy` or
`model_not_allowed_by_security_policy` when that profile no longer allows the
saved repository, a GitHub trigger repository, or the model; a save the
policy refuses keeps the editor open with the reason. Someone without
`security.manage` editing a workflow that keeps another profile sees every
choice; saving still checks it.

These limits govern Moyai-managed access only. They do not stop a session's shell
from cloning a public repository, using credentials a person supplies, or calling
another model provider with its own key. Exclude the credential tools in the same
policy where that matters.

New native sessions pin the selected/default profile's revision and complete
policy in one admission transaction. PostgreSQL rejects updates and deletes of
that binding. Profile edits affect new sessions. The current mandatory policy
also applies at execution, including to older native sessions. Delegated sessions
inherit their parent's effective snapshot instead of adopting an unrelated new
default; mandatory policy remains live.

Only `security.manage` holders can enumerate profiles or explicitly choose one
from Home or workflow configuration. Other users receive the organization default.
A workflow may retain its saved profile without regaining policy-management
permission. Workflow edits recheck selection and the connected-app, repository
(including GitHub trigger repositories) and model limits inside the writer
transaction. A workflow created or updated by an agent cannot exceed the
creating session's effective policy. Both scheduled and event-triggered
admissions bind that workflow's profile before admitting work. A run refused by
that profile, the effective policy or the owner's role is recorded as blocked,
and the workflow stays blocked until its owner enables it again.

Native tool catalogs omit disallowed operations. Tool execution checks the policy
again, including every Temporal activity attempt. Managed connection credential
release and repository/environment preparation also recheck access. Git policy
controls Moyai-managed GitHub operations; it does not inspect arbitrary shell text
or files already present on a session computer.

### Network allowlists

**Network allowlists are enforced only on Modal computers, and only after an
operator sets `MOYAI_NETWORK_POLICY_ENFORCEMENT=modal`** (the default is `off`).
Otherwise native admission, tool checks, model admission and workflow
configuration refuse any policy with a non-null `network_domains` value,
including an empty list, and a default or mandatory profile with network
restrictions stops new and running native sessions. Lambda computers always
refuse restricted policies: `LAMBDA_EGRESS_CONNECTOR` is deployment-wide. A
session's provider is that of its existing computer, otherwise
`SANDBOX_PROVIDER`, so changing the default never admits a restricted session on
an existing Lambda computer.

With enforcement on, the session's effective domains (its binding intersected
with the live mandatory policy) are passed to Modal when its computer is created:
on the agent's first workspace use, in continuation preparation, and when a
checkpoint is restored. An empty list creates an allowlist with no entries, not
Modal's `block_network`. An unrestricted session's computer is created exactly as
before. A restricted computer records a digest of its creation-time allowlist in
an immutable Modal sandbox tag. Every agent workspace or tool activity, human
desktop or browser action, desktop stream, and preparation that reuses a computer
compares that tag with the session's current effective policy, and refuses a
computer created under a wider policy before anything runs in it. The tag holds
only a digest, so a computer created under any other restricted list, even a
narrower one, is refused as well. Computers created before this release have no
tag and count as unrestricted.

A narrowed mandatory policy therefore stops further work in running computers;
processes already running in one keep its creation-time policy until it stops.
Preparation reports the refusal; an agent step that meets such a computer ends
the turn as an unavailable computer. Start a new chat, or continue after the
computer stops: the next turn restores the saved files into a computer created
under the current policy. Removing a session's network restriction needs no
action; any other change to its allowlist needs a new computer. The setting
decides admission only; workers always create computers under the session's
policy.

Modal matches outbound TLS on port 443 by SNI hostname; `*.example.com` covers the
apex and every subdomain. Plain HTTP (including Debian `apt` mirrors), SSH,
`git://` and other ports and protocols are blocked. **DNS lookups are not
restricted**, so DNS tunnelling remains possible, and allowing a shared CDN domain
such as `*.cloudfront.net` allows the other sites it serves (domain fronting).
Restricted sessions must list package registries such as `pypi.org`,
`files.pythonhosted.org` and `registry.npmjs.org` themselves. The policy covers
the session computer only: Moyai's own model gateway, managed connector, Git fetch
and object storage traffic, and image builds, are governed by connected apps, Git
access and operator configuration instead. CIDR entries, narrowing running
computers live, mid-session destination approvals and audit events for network
refusals are not implemented.

Keep the setting `off` until every API, worker, broker and coordinator runs this
release, use the same value in every service, and first run the
[operator egress probe](modal-runtime.md#outbound-network-allowlists) against your
Modal workspace under the deployed runtime. Modal documents the domain allowlist
as beta. An older worker creates untagged computers, which restricted sessions
refuse, so a mixed rollout fails closed.

## Spend limits

Configure organization and per-person UTC calendar-month limits, a default
lifetime session limit, and per-email overrides. `null` means unlimited; zero
blocks new paid model requests. Per-email totals include all canonical actors
with that email. A session's total includes its delegated descendants, and a
child must also remain below every ancestor's session budget.

The inference admission transaction that records the durable request receipt
checks the budget. Requests still in flight neither count nor block concurrent
admission, so concurrent work can cross a limit by its in-flight cost. A request
stops counting as in flight one minute after the model timeout
(`MOYAI_MODEL_TIMEOUT`), even if its final status was never recorded. A finished
request without a reported cost fails closed for every limited scope it counts
toward while receipt recovery can still settle it, for at most 24 hours, or
one hour once LiteLLM reports it has no log for that request.
Requests known not to have dispatched, requests the gateway answered with an
error status (LiteLLM records those at zero spend), and duplicate receipts whose
charge another request carries do not consume budget. A cost that recovery
cannot settle (recovery disabled, a rotated gateway key, rejected receipt
evidence, or a request older than 24 hours) stops blocking; Spend limits reports
it as unresolved for a spend manager to review. Reported final USD costs come
from the native inference ledger; no prices are invented for missing receipts.
These are admission limits, not provider-side prepaid reservations. Already
dispatched work is not cancelled by a limit change. Without a configured limit,
admission reads no usage.

Native turns stream, and a streamed request's cost arrives only in its final
event. Before configuring a limit, have the gateway report it there (for LiteLLM,
`include_cost_in_streaming_usage: true` under `litellm_settings`; confirm that a
test request records a cost on the Spend limits page). Otherwise every finished
request is unpriced: each limited scope refuses new requests until recovery
settles the previous ones, and with recovery disabled the limits never block.

A session budget reads only its delegation family, through the family root
bound with each session. Organization and per-person budgets sum the month's
ledger rows on every model request, inside the admission transaction, so that
check grows with the month's request volume. The ledger keeps its existing time,
actor and session indexes. A covering index or running totals would change the
ledger that the billing-storage consolidation copies and re-indexes, so they need
a reviewed billing-storage migration.

Native Slack intake does not transcribe audio, since gateway transcription is
neither admitted against these limits nor recorded in the ledger. The original
file remains available to the agent.

## AI guardrails

Moyai has no prompt classifier of its own. Configure guardrails in the LiteLLM
gateway: every native model request (web, Slack, workflows, delegated and team
tasks, and memory review) passes through it, including the tool output the agent
sends back to the model. Moyai selects no guardrails per request, so make each one
`default_on` or attach it to Moyai's virtual key or team, and do not set
`disable_global_guardrails` or `opted_out_global_guardrails` in that key's or
team's metadata. For PHI, use a self-hosted or BAA-covered backend, such as
Presidio, AWS Bedrock Guardrails or Azure Prompt Shields; a third-party guardrail
service receives every screened prompt and tool output.

```yaml
guardrails:
  - guardrail_name: phi-presidio
    litellm_params:
      guardrail: presidio
      mode: pre_call
      default_on: true
      presidio_analyzer_api_base: https://presidio-analyzer.internal
      presidio_anonymizer_api_base: https://presidio-anonymizer.internal
      pii_entities_config:
        US_SSN: BLOCK
        MEDICAL_LICENSE: BLOCK
```

Moyai recognizes a refusal from a `pre_call` or `during_call` guardrail, which
LiteLLM returns before any model output as an OpenAI error with status 400, 403
or 422, the statuses LiteLLM itself counts as a guardrail block. The error must
name its guardrail in one of two ways that LiteLLM 1.106.4 uses:

- `error.provider_specific_fields.guardrail_name`, which LiteLLM adds when a
  guardrail raises an HTTP error with structured detail, as Bedrock, Lakera v2,
  Aporia, Azure and the LiteLLM content filter do.
- LiteLLM's own wrapper in `error.message`, "Guardrail raised an exception,
  Guardrail: <name>, ..." or Presidio's "... by Guardrail: <name>. ...", with a
  name that `x-litellm-applied-guardrails` also lists.

Guardrails that raise their own unwrapped message are not recognized: the
generic guardrail API, whose message is the backend's `blocked_reason` or
"Content violates policy", Akto and Alice, for example. Other statuses are never
refusals. A guardrail backend that is unavailable, throttled or answers
unexpectedly (a 5xx, 408 or 429, such as Bedrock's "throttle retries exhausted"
or the generic guardrail API's "Generic Guardrail API failed") fails the turn
with the generic failure and records no event. LiteLLM does not report whether a
wrapped guardrail exception judged the content, so a guardrail that fails closed
with that wrapper and status 400 when its backend is unreachable (LLM Shield
Proxy, for example) still counts as a refusal. Check the gateway logs before
treating such an event as the requester's violation. The
`x-litellm-applied-guardrails` header alone is not proof of a refusal, because
LiteLLM also sends it on ordinary provider errors after guardrails pass. A
`MASK` action rewrites the request instead of refusing it, and Bedrock's
`disable_exception_on_block` returns the guardrail's message as a successful
answer; neither is a refusal to Moyai. A `post_call` guardrail that fails a
streamed answer mid-stream looks like an ordinary stream error.

A recognized refusal fails the turn with the non-retryable `MoyaiGuardrailBlocked`
denial, so Temporal never sends the refused input again. The web failure banner
and the Slack thread show "Your organization's AI guardrail blocked this
request."; the Slack report omits its debug log, which would repost the refused
prompt and tool output, and so does a Slack report whose failure record cannot be
read. The turn's conversation is not saved as the next turn's context, so its
files are not checkpointed either. The submitted message stays in the
transcript, but later turns leave it out of the context they rebuild from
earlier messages when the requester, model or connections change, and out of the
Slack thread they read, so another participant's turn does not send it again. A
refused memory review is settled once, without retries.

Each refusal records one `ai_guardrail.violation` audit event, in the same
transaction as its zero-spend ledger outcome, with the requester as the actor.
The resource is the refusing guardrail's name, or `gateway` when the name LiteLLM
reported is not a valid guardrail name. Details hold only the session ID, model,
guardrail mode, and the names in `x-litellm-applied-guardrails`; never prompts,
tool output, or the guardrail's response. Retried attempts of one model activity
share one event. Filter the audit log by the `ai_guardrail` resource type, or
export it, to list violations. A refusal Moyai does not recognize is still
blocked by the gateway, but the turn shows the generic failure and records no
event.

Without gateway guardrails, nothing is screened. To fail closed instead, set
`MOYAI_REQUIRED_GUARDRAILS` to at most ten comma-separated guardrail names
(letters, digits, `_`, `.`, `:` and `-`); order and repeats do not matter. Like
the other shared runtime settings, every role needs the same names: change them
by restarting the coordinator first, since other roles with different names are
refused. While it is empty, the setting leaves the role contracts unchanged. Each
successful answer must then list every name in `x-litellm-applied-guardrails`,
which LiteLLM sends with the response headers before any streamed content.
Otherwise the broker (or, without a separate broker, the process that dispatches
the request) closes the answer before the agent reads any of it, records
`ai_guardrail.unattested` with the missing names, and fails the turn with the
non-retryable `MoyaiGuardrailUnattested` denial ("The model gateway did not
confirm your organization's required AI guardrails, so this request was
stopped."). The gateway has already processed that request; its cost settles
like an interrupted stream. LiteLLM 1.106.4 lists a passing guardrail only when
the guardrail records itself: Presidio, Bedrock, the LiteLLM content filter, the
generic guardrail API and Lakera v2 do, while Azure Prompt Shields does not. Send
a test request and check the header before setting this, or every request is
refused.

## Audit and API

The audit feed combines metadata-only role, SCIM, policy, spend, credential, and
connection changes, AI guardrail refusals and attestation failures, and
organization OpenID Connect enrollment and sign-in (`identity_binding.created`,
`sign_in.succeeded`, and `sign_in.refused` with a fixed reason). Filters and
signed cursors bound each page. Only the first page
(no cursor) carries the filter facets, as only the provisioning directory's first
page carries its groups, tokens and activity. CSV/NDJSON exports stream pages of up
to 1,000 rows and recheck live permission before releasing each page. Tokens,
credential contents, prompts, policy domain, tool, repository and model payloads,
and identity provider tokens, codes and claims are excluded from governance events.
Apart from AI guardrail refusals, attestation failures and sign-in, this records
configuration history, not a transcript of every agent action.

| Endpoint | Purpose |
| --- | --- |
| `/api/admin/roles`, `/api/admin/role-assignments`, `/api/admin/group-roles/{id}` | Roles and grants |
| `/api/admin/scim`, `/api/admin/scim/tokens` | Provisioning administration |
| `/scim/v2/*` | Bearer-authenticated directory protocol |
| `/api/security-profiles` | Enabled profile selection catalog |
| `/api/admin/security-profiles`, `/api/admin/security-profiles/defaults` | Revision-checked policy configuration, with the editor's app, tool, repository and model choices and the deployment's network enforcement |
| `/api/security-policy/new-session` | Policy and default model a new session would get; `sessions.create`, and `security.manage` to name a `profile_id` |
| `/api/sessions/{id}/security-policy` | Accessible session's effective policy |
| `/api/admin/spend-limits` | Spend configuration and reported usage |
| `/api/admin/governance/audit`, `/api/admin/governance/audit/export` | Audit feed and export |

Configuration writes reuse canonical optimistic revisions, live writer-fenced
permissions, CSRF protection for browser requests, and transaction-local audit
records. A policy update must include `repositories` and `models` whenever the
saved policy limits them; an older editor or script that omits them is refused
(409) instead of clearing the limits. Standalone native mode keeps its existing
built-in account behavior; these enterprise settings require the canonical
existing-product deployment.
