# Enterprise governance

Governance is enforced by the native Pydantic runtime in existing-product mode
(`MOYAI_PRODUCT_MODE=existing`). Settings includes Roles & access, Provisioning,
Security policies, Spend limits, and Audit log. The retired execution engine is
not required.

## Deployment and migration

Apply canonical schema revision **23** and native application migration
**2026-10-21-product-governance-v24** during the coordinated maintenance window
in [the deployment contract](pydantic-deployment.md). Canonical revision 23 combines
upstream revision 22 with the governance branch's older revision 22; neither older
layout is admitted as the combined release. The native migration follows upstream
v23 (automation chats), adds an immutable session-policy table and preserves the
previous 23 migration receipts. It installs a trigger, so it is not an
[online expansion](native-online-schema.md). Normal startup verifies both schemas;
it does not run migrations.

The canonical upgrade retains existing governance configuration and audit events,
copies the older `floor_profile_id` into the mandatory policy, and adds SCIM
revocation epochs. Previously inactive directory users remain revoked. Existing
native sessions without policy bindings have no selected profile, and are still
subject to the current mandatory policy. A continuation of a historical governed
session intersects its saved policy with the new native binding.

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

The server checks permissions independently of navigation visibility. Native
session and turn admission, tool catalogs, actual tool attempts and retries,
connection credentials, model dispatch, memory recall, and workspace preparation
resolve current authority. Role changes and SCIM revocations invalidate saved
execution grants. Reactivation does not restore an earlier revoked grant.

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
`read`, or `none`), and network destinations. For apps, tools, and domains,
`null` is unrestricted, an empty list permits nothing, and a populated list is an
allowlist. Intersections can only narrow a bound policy. Git access `none` also
refuses GitHub connections. Slack has no account picker, so a Slack message
selects only the connections its session policy and the sender's role allow.

New native sessions pin the selected/default profile's revision and complete
policy in one admission transaction. PostgreSQL rejects updates and deletes of
that binding. Profile edits affect new sessions. The current mandatory policy
also applies at execution, including to older native sessions. Delegated sessions
inherit their parent's effective snapshot instead of adopting an unrelated new
default; mandatory policy remains live.

Only `security.manage` holders can enumerate profiles or explicitly choose one
from Home or workflow configuration. Other users receive the organization default.
A workflow may retain its saved profile without regaining policy-management
permission. Workflow edits recheck selection and connected-app/repository limits
inside the writer transaction. A workflow created or updated by an agent cannot
exceed the creating session's effective policy. Both scheduled and event-triggered
admissions bind that workflow's profile before admitting work. A run refused by
that profile, the effective policy or the owner's role is recorded as blocked,
and the workflow stays blocked until its owner enables it again.

Native tool catalogs omit disallowed operations. Tool execution checks the policy
again, including every Temporal activity attempt. Managed connection credential
release and repository/environment preparation also recheck access. Git policy
controls Moyai-managed GitHub operations; it does not inspect arbitrary shell text
or files already present on a session computer.

**Current Modal and Lambda computer adapters cannot enforce outbound network
allowlists.** Native admission, tool checks, and model admission therefore refuse
any policy with a non-null `network_domains` value, including an empty list. A
default or mandatory profile with network restrictions stops new and running
native sessions. This release does not claim machine-level egress support.

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
toward while receipt recovery can still settle it, for at most 24 hours.
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

## Audit and API

The audit feed combines metadata-only role, SCIM, policy, spend, credential, and
connection changes. Filters and signed cursors bound each page. CSV/NDJSON exports
recheck live permission before releasing each chunk. Tokens, credential contents,
prompts, and policy domain/tool payloads are excluded from governance events.
This records configuration history, not a transcript of every agent action.

| Endpoint | Purpose |
| --- | --- |
| `/api/admin/roles`, `/api/admin/role-assignments`, `/api/admin/group-roles/{id}` | Roles and grants |
| `/api/admin/scim`, `/api/admin/scim/tokens` | Provisioning administration |
| `/scim/v2/*` | Bearer-authenticated directory protocol |
| `/api/security-profiles` | Enabled profile selection catalog |
| `/api/admin/security-profiles`, `/api/admin/security-profiles/defaults` | Revision-checked policy configuration |
| `/api/sessions/{id}/security-policy` | Accessible session's effective policy |
| `/api/admin/spend-limits` | Spend configuration and reported usage |
| `/api/admin/governance/audit`, `/api/admin/governance/audit/export` | Audit feed and export |

Configuration writes reuse canonical optimistic revisions, live writer-fenced
permissions, CSRF protection for browser requests, and transaction-local audit
records. Standalone native mode keeps its existing built-in account behavior;
these enterprise settings require the canonical existing-product deployment.
