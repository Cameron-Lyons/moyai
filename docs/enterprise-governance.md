# Enterprise governance

Moyai has workspace permissions, custom roles, SCIM provisioning, session security
profiles, and a shared governance audit history. Open **Settings → Governance**
(`/#governance`) to administer them. Tabs appear according to the signed-in
person's permissions: **Roles**, **Provisioning**, **Security policies**, and
**Audit history**. Existing sign-in protocols and private-session ownership rules
remain in effect; provisioning does not create a browser login.

This guide describes the current source. The changes require schema revision
**20** and a coordinated release. Local tests do not establish a production
deployment, identity-provider certification, or live sandbox-provider enforcement.

## Roles and permissions

The built-in **Administrator** (`admin`) retains all catalog permissions. The
built-in **Internal user** (`member`) retains its existing session, personal
skills/memory/credentials, workflow, and personal-spend access. Built-in roles
cannot be edited or archived. People without an explicit custom assignment keep
their existing administrator/internal-user defaults.

For an eligible verified work email, a custom assignment replaces the internal
user's default permission set. Active directory-group grants then add permissions
by union. For example, a custom role with `workspace.read`, `sessions.read`, and
`spend.personal` can inspect accessible work but cannot start a session; adding a
group role with `sessions.create` enables that action for its active members.
Permission checks apply to API requests and runtime admission, not just hidden
buttons. Broker tools are filtered and checked against their corresponding
permissions, including direct Git, artifact, and goal transports. Permission to
start a session does not restore removed workflow, library, or connection access.
These checks do not make a shared conversation private.

`connections.read` allows viewing connections and using enabled app read tools.
`connections.write` allows enabled app write tools; `connections.manage` controls
connection setup and organization policies. Internal users retain read and write
tool access under those policies. A custom reader can omit `connections.write`,
and a session profile can further restrict individual tools and destinations.

Role permissions come from the explicit catalog returned by `GET /api/permissions`
and the role editor. Relevant governance permissions are:

| Permission | Access |
| --- | --- |
| `users.read` | Read the user directory |
| `users.manage` | Change built-in user assignments |
| `roles.manage` | Manage custom roles, email assignments, and group grants |
| `scim.manage` | Manage provisioning credentials and view the provisioning directory |
| `security.manage` | Manage security profiles and organization defaults |
| `audit.read` | Read governance audit history |

Use **Roles → Create role**, select catalog permissions, and save. Use **Assign
role** to assign a built-in or custom role to a work email. The existing
**Settings → Users** page remains available for built-in assignments. Assignments
do not grant sign-in eligibility to an external email, and neither a Slack
accounting link nor an unverified profile grants elevated web permissions.

Changes apply on the next authorized request. Edits use revisions; a stale edit
returns `409` and must be reloaded. Archiving a custom role removes its permissions
from direct assignments and group grants immediately. An assignment to an archived
role does not fall back to the internal-user defaults. Active group grants can
still add their own permissions. Assign a replacement role before archiving when
continued access is intended.

Under **Provisioning → Assign group role**, map a provisioned group to a custom
role or the internal-user role. Choose **No additional permissions** to remove
the grant. The built-in administrator role must be assigned directly to a person;
it cannot be assigned to a directory group. User deactivation, group deletion,
membership removal, and role archival remove the corresponding group permissions.

Built-in administrator demotion and SCIM deactivation/deletion run their
last-administrator checks inside the same serialized transaction as the change.
Keep at least one eligible active administrator. Concurrent attempts to deactivate
the final two administrators cannot remove both.

## Connect an identity provider with SCIM

1. In **Provisioning**, select **Create token** and give the credential a useful
   label, such as the directory provider and environment.
2. Copy the bearer token immediately. It is shown only once. The server stores
   its SHA-256 hash, a nonsecret prefix, and lifecycle metadata, not the bearer
   secret. Browser and SCIM cookies cannot substitute for this credential.
3. In the identity provider's SCIM application, set the base URL to the exact URL
   displayed in Moyai, normally `https://your-workspace.example/scim/v2`, and
   supply the token as `Authorization: Bearer <token>`. Use HTTPS outside local
   development. Set `userName` to the person's work email and, where available,
   `externalId` to the directory's stable user identifier.
4. Enable the supported user and group mappings below. Provision a test person
   and group, confirm them in Moyai, and map the group to a workspace role if
   additional permissions are needed.
5. Verify the complete lifecycle with that test person: create, membership
   update, `active: false`, attempted access, and reactivation. Rotate the
   credential by creating a replacement, updating the provider, verifying its
   requests, and revoking the old token.

Revocation blocks the old credential's next request, including a mutation whose
body was parsed before revocation but whose write transaction has not started.
Revoking a provisioning token retains saved users, groups, and their access state.
It is a credential change, not bulk deprovisioning. There is no automatic token
expiry or provider-managed OAuth issuance in this adapter.

With Cloudflare Access enabled, the application exempts only the installed SCIM
controller paths and their supported methods from employee-assertion checking.
Every exempt controller still requires the provisioning bearer token. Browser,
admin, broker, unknown SCIM paths, and unsupported method/path combinations keep
their Access checks. Configure the **Cloudflare edge** separately to admit the
SCIM provider through an appropriate service-token or narrowly scoped bypass
policy; the application cannot change that external policy. See
[Cloudflare Access](cloudflare-access.md) for the existing access configuration.

### Supported protocol surface

The adapter follows the [SCIM core schema](https://www.rfc-editor.org/rfc/rfc7643)
and [HTTP protocol](https://www.rfc-editor.org/rfc/rfc7644) for this explicit subset.
Responses use `application/scim+json`; JSON writes accept that media type or
`application/json`. Errors return the SCIM Error schema, string `status`, `detail`,
and an applicable `scimType`. Unauthorized calls return `401` with a Bearer
challenge.

| Endpoint | Supported operations |
| --- | --- |
| `/ServiceProviderConfig` | Authenticated `GET`; advertises the supported capabilities |
| `/ResourceTypes`, `/ResourceTypes/User`, `/ResourceTypes/Group` | Authenticated `GET` |
| `/Schemas`, `/Schemas/{core-schema-URI}` | Authenticated `GET` for User and Group |
| `/Users` | List/filter with `GET`; create with `POST` |
| `/Users/{id}` | Read with `GET`, replace with `PUT`, update with `PATCH`, delete with `DELETE` |
| `/Groups` | List/filter with `GET`; create with `POST` |
| `/Groups/{id}` | Read with `GET`, replace with `PUT`, update with `PATCH`, delete with `DELETE` |

Users support `userName`, `externalId`, `active`, `displayName`, `name`, `emails`,
`title`, `userType`, `nickName`, `preferredLanguage`, `locale`, `timezone`, and
`profileUrl`. `userName` is a normalized, case-insensitive work email and is
immutable. For an email migration, deactivate the old identity and provision the
new email through an explicit account transition. Optional profile fields omitted
by `PUT` are removed; omitted `active` defaults to `true`. User `groups` is a
read-only view of direct membership. Core-schema extensions and passwords are not
supported.

Groups support `displayName`, `externalId`, and direct User `members`. Membership
values must reference existing, nondeleted provisioned user IDs. Nested groups
are unsupported. Group updates and all their membership changes commit together;
an invalid member rolls the update back. Group names are unique case-insensitively
among live groups; nonempty external IDs are unique within each live resource
type.

`PATCH` uses `urn:ietf:params:scim:api:messages:2.0:PatchOp` with an `Operations`
array. Supported operations are `add`, `replace`, and `remove`, with direct
supported attribute paths, individual `name` subattributes, or object-valued
add/replace without a path. Group membership additions/replacements use arrays;
removing all `members` or one `members[value eq "<user-id>"]` is supported.
Unsupported filtered paths fail explicitly. Required/immutable/read-only
attributes cannot be removed or rewritten through PATCH.

Lists accept only `filter`, `startIndex`, and `count`. Pagination starts at 1,
returns at most 100 resources, and reports `totalResults`, `startIndex`, and
`itemsPerPage`; `count=0` returns metadata without resources. Each request is a
fresh list, so concurrent provisioning can change pages. Supported filters are:

| Resource | Exact filter forms |
| --- | --- |
| Users | `userName eq "person@example.com"`, `externalId eq "directory-id"`, `id eq "resource-id"`, `active eq true`, `active eq false` |
| Groups | `displayName eq "Engineering"`, `externalId eq "directory-id"`, `id eq "resource-id"` |

User-name and group-display-name comparisons ignore case; IDs/external IDs retain
their exact values. Boolean filter values must be unquoted. Compound filters,
other operators, attribute projection, sorting, bulk operations, `.search`,
password changes, and ETags are not implemented. Unsupported query/filter forms
return an error rather than silently broadening the result. Requests are limited
to 2 MiB, PATCH to 100 operations, groups to 10,000 submitted members, and user
email arrays to 20 entries. Test the selected provider's mappings against this
surface before relying on automated provisioning.

### Deactivation and retained identities

For a provisioned email, `active: false` invalidates existing signed-in access on
the next request and denies new runtime/tool admissions. Known Slack senders are
checked through their profile email and linked identity. A directory with SCIM
entries requires an unknown Slack sender to obtain a verified provider profile
before accepting work; enable Slack identity linking and the existing
`users:read` and `users:read.email` scopes. Missing profile permissions or lookup
failures fail closed. Already-running unknown Slack actors also cannot continue
through the broker until mapped to a verified profile.

Deletion returns `204`, removes membership, and hides the resource from SCIM
reads. An inactive email tombstone remains so a saved session cannot regain
access merely because its SCIM row disappeared. Reprovisioning the same email
creates a new resource ID and can restore access; an explicit `active: true` also
reactivates a live resource. Unmanaged emails keep the existing workspace access
rules. Shared password/local-preview identities are not individual SCIM users.
An operation already dispatched cannot be recalled; deactivation stops subsequent
authorized actions, not an external write already accepted by its destination.

## Security profiles for agent sessions

Under **Security policies**, create a named profile with any combination of
allowed connected apps, allowed broker tool names, managed Git access, and exact
network hostnames. Set the **Default policy** for new sessions and the
**Mandatory policy** for workspace-wide constraints. A person's role determines
which application actions they may perform; a profile further restricts what an
agent session may do with its allowed tools and connections.

| Profile field | Meaning |
| --- | --- |
| `connected_apps` | Allowed managed `github`, `linear`, `slack`, and `notion` connections |
| `tools` | Allowed broker tool names |
| `git_access` | `write`, `read`, or `none` for managed GitHub operations |
| `network_domains` | Exact DNS hostnames allowed by the sandbox egress policy |

For list fields, `null` imposes no profile restriction and `[]` permits no entries.
Hostnames exclude URL schemes, paths, ports, wildcards, and IP addresses. Names
are normalized to lower-case IDNA DNS names. Connection policies, selected
repositories, exact-PR authority, and ordinary tool authorization still apply.
Managed Git read-only blocks publication; it does not remove existing checkout
files. The GitHub installation credential stays on the broker.

New-session **Context → Security policy** and the workflow editor's **Security
policy** select a profile; an empty selection uses the organization default.
Saving a session pins the selected revision and a serialized policy snapshot.
Editing that profile later affects future bindings, not the saved snapshot.
Children and side chats inherit restrictions from their ancestors; selecting a
broader child profile cannot loosen them. The current mandatory policy intersects
with those snapshots at execution, so it can further restrict existing sessions.
Relaxing the mandatory policy does not relax an already-pinned stricter snapshot.
Create a new session when broader authorized access is needed.

An enabled profile used as the default or mandatory policy cannot be disabled
until removed from those defaults. Profile/default edits are revision checked.
Changing the mandatory **network** restriction requires releasing live session
computers and independent-runtime guests first; the server returns `409` while
any such machine remains. Let work finish and release its retained machines,
then retry the change. Closing a Computer tab alone is not a machine release.

### Network and provider enforcement

Domain restrictions require **Substrate**. Modal and AWS Lambda MicroVMs reject
sessions with a non-null network allowlist, including an empty allowlist, before
starting their machine because this adapter cannot enforce that policy there.
Profiles without a domain restriction can still restrict managed apps/tools/Git
on those providers.

Substrate installs the actor's egress policy before resume/guest activation. When
a restored or named actor already has a policy, Moyai replaces it using the
provider's current UID/version before resuming. Update errors fail closed. Exact
session hostnames are intersected with the operator's `SUBSTRATE_EGRESS_HOSTS`
ceiling; a session cannot widen that provider configuration. The existing native
wildcard syntax in the global ceiling matches one DNS label, not arbitrary nested
subdomains.

Moyai adds the broker's `PUBLIC_URL` hostname as required infrastructure. An empty
session domain list therefore allows only that broker destination, subject to
the global ceiling. Include the broker hostname in the global provider ceiling
and include dependency registries/application hosts in the selected profile when
the task needs them. The broker retains model and managed-app secrets.

App/tool/Git fields govern managed broker operations. They do not disable a
harness's native shell commands or prevent local file edits. For native shell,
browser, and other guest network activity, use the provider-enforced domain policy.
This is a host-level egress boundary, not a URL-path allowlist or a promise to
filter content sent to an allowed host. Prepared project builds remain their
separate administrator-managed setup workflow; select suitable setup recipes and
provider access for those builds.

## Audit history and API routes

**Audit history** combines role/assignment changes, provisioning resource and
credential changes, profile revisions, and organization security-default changes.
The shared feed exposes action, authenticated actor, resource type/identifier,
and timestamp. It does not include provisioning bearer secrets, profile policy
bodies, raw user content, or arbitrary mutation payloads. Failed/rolled-back
mutations do not produce successful-change entries. This is governance history,
not an audit of every model request, file read, or tool action; see existing
[tracing](observability.md) for execution records.

| API | Purpose |
| --- | --- |
| `GET /api/permissions` | Effective caller permissions and catalog |
| `/api/admin/roles`, `/api/admin/roles/{role_id}` | Custom-role list/create/update/archive |
| `PUT /api/admin/role-assignments` | Direct email assignment |
| `PUT /api/admin/group-roles/{group_id}` | Directory-group grant |
| `GET /api/admin/scim` | Directory, token metadata, and recent provisioning activity |
| `POST /api/admin/scim/tokens`, `DELETE /api/admin/scim/tokens/{id}` | Create/revoke provisioning credentials |
| `GET /api/security-profiles` | Enabled session-selection catalog |
| `/api/admin/security-profiles`, `/api/admin/security-profiles/{id}` | Profile administration |
| `PUT /api/admin/security-profiles/defaults` | Default and mandatory profiles |
| `GET /api/admin/governance/audit` | Shared governance feed |

Browser mutations retain origin/CSRF checking. Each governance route requires
its corresponding catalog permission. Audit pages default to 50 entries and
allow 1–100; follow `next_cursor` for earlier entries in the same snapshot.
Cursors are signed and expire after 24 hours. Refresh to see changes committed
after the first page.

## Operator rollout and verification

This release raises both the physical schema and compatibility baseline to
**20**. It is a coordinated offline migration, not an automatically compatible
rolling expansion.

1. Back up the target database and retained files. Keep the existing signing and
   encryption keys, shared settings, database/schema, and resource ownership.
2. Drain current work and stop **all** application, API, coordinator, broker, and
   worker database owners using the established maintenance procedure. The
   migrator refuses live owners; it does not stop them or cancel their work.
3. From the reviewed target checkout and its configured deployment environment,
   run:

   ```sh
   uv run --frozen --python 3.13 python -m app.schema_migrations --apply
   ```

   Require `{"schema_revision": 20, "status": "ready"}`. Explicit migration
   requires PostgreSQL plus the existing explicit `SESSION_SECRET` and
   `ENCRYPTION_KEY`. Initializing an empty schema also requires the existing
   `MOYAI_DATABASE_INITIALIZE=true` setting.
4. Start matching application/broker/worker images and roles with
   `MOYAI_SCHEMA_MODE=verify` for an explicitly migrated PostgreSQL deployment.
   Follow the ownership/startup order in the
   [schema migration procedure](schema-migrations.md#first-activation-coordinated-maintenance).
   Verify health, retained sessions, governance tabs, a restricted-role request,
   SCIM deactivation, and restricted-session admission before reopening work.
5. Configure the directory and profiles using the steps above. This document and
   the source changes do not apply a migration, modify external IdP/Cloudflare
   policy, or deploy production.

SQLite retains its existing automatic local schema setup. Verified PostgreSQL
roles do not perform feature DDL during normal startup. Run the focused local
regressions against the repository's pinned environment:

```sh
uv run --frozen --python 3.13 pytest -q tests/test_enterprise_roles.py tests/test_scim.py tests/test_security_profiles.py tests/test_governance_audit.py tests/test_governance_integration.py tests/test_user_roles.py tests/test_cloudflare_access.py tests/test_schema_migrations.py
```

For database conformance, use a **disposable** PostgreSQL database; the existing
test harness creates and removes isolated schemas:

```sh
MOYAI_TEST_POSTGRES_URL=postgresql:///postgres uv run --frozen --python 3.13 pytest --postgres-backend -q tests/test_enterprise_roles.py tests/test_scim.py tests/test_security_profiles.py tests/test_governance_audit.py
```

These tests cover real application authorization and database transactions with
simulated external providers, including concurrent last-admin deactivation,
credential revocation before dispatch, atomic membership updates, live-session
revocation, exact Access exemptions, profile inheritance, and fail-closed provider
admission. They do not certify an IdP integration or a deployed Substrate cluster.

## Dedicated organization deployments

The organization architecture is **one organization per dedicated deployment**.
Deploy each organization with its own database/schema, storage resources,
signing/encryption keys, app connections, sandbox resources, and appropriately
restricted database/cloud credentials. Multiple application roles or replicas
inside one deployment still share that organization's workspace. Personal and
private-session controls operate within that workspace.

Set `MOYAI_ORGANIZATION_ID` before initializing a fresh deployment, for example:

```dotenv
MOYAI_ORGANIZATION_ID=acme
```

An ID is at most 32 characters, starts with a lower-case letter, and uses
lower-case letters, digits, and single hyphens between nonempty segments. Use
the same ID on the API, coordinator, broker, and every worker. The database pins
that identity immutably. A pinned database refuses startup with a different or
missing ID; changing an environment variable cannot repurpose it for another
organization.

The ID scopes infrastructure defaults idempotently:

| Resource | Organization-specific name |
| --- | --- |
| Temporal namespace and task queue | Append `-org-<id>` |
| Modal app and checkpoint volume | Append `-org-<id>`; the Modal deployment wrapper also scopes its configuration secret |
| Substrate atespace | Append `-org-<id>` |
| Object storage and Lambda checkpoint prefixes | Append `/organizations/<id>` |

Names retain the provider length limits. Configuration round trips and saved
sandbox settings do not append the suffix twice. Provision the derived Temporal
namespace, Substrate atespace/templates, and other required resources through
their existing setup procedures before admitting work. Inspect the effective ID
and namespace values through authenticated `GET /api/organization`; its
`deployment` object reports the dedicated-deployment metadata. See the
[Substrate](substrate.md) and [Lambda MicroVM](aws-lambda-microvms.md) setup guides
for those providers.

Browser session/CSRF/cursor signing and durable runtime capabilities also use the
organization context. Separate database and storage authorization remain necessary:
a prefix or resource name alone does not enforce cloud IAM isolation. Keep each
organization's resource credentials scoped to its own database, buckets/prefixes,
Modal resources, and Substrate atespace.

An empty ID preserves an existing deployment's names and keys. An explicit ID
cannot be adopted automatically by a populated, previously unpinned database:
renaming its workflow namespaces, snapshots, checkpoints, or connections would
strand retained work. Keep that legacy deployment's ID unset, or prepare an
operator-reviewed namespace/data migration separately; new organization
deployments should use fresh storage and an explicit ID.

This architecture provides separate organization deployments. It does not add an
organization switcher or a shared multi-tenant control plane to one application
instance. Local two-deployment isolation tests do not establish external IAM
permissions or a deployed cloud configuration.
