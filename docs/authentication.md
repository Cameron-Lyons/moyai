# Sign-in and user roles

Local trials use native accounts. Set `WORKSPACE_PASSWORD` before first start,
sign in as `admin`, and manage users in Settings. Passwords are hashed; role and
enabled-state changes invalidate prior authorization. The final enabled
administrator cannot be removed or demoted.

Existing-product mode uses the canonical Moyai identity directory, signing
secret, cookie and role records. It cannot bootstrap a replacement native admin.
Historical private ownership, personal credentials and Slack identity links keep
their original account IDs. Native projections are created only after canonical
authentication succeeds.

## Google and Cloudflare

Keep existing Google OIDC settings and `PUBLIC_URL/auth/google/callback` registered
at the provider. Google verifies issuer, audience, signature, expiry, nonce,
verified email and allowed hosted domain. `GOOGLE_ADMIN_EMAILS` supplies defaults
for identities without an explicit saved role; stored role assignments win.
Use the canonical Users page for role changes, which checks optimistic revisions,
last-admin protection and the current actor within the write transaction.

If Cloudflare Access is enabled, retain its existing audience, team and identity
policy. With `CLOUDFLARE_ACCESS_LOGIN=true`, Moyai verifies the employee assertion
on each request and maps it to the canonical identity. A plain forwarded-email
header or machine token cannot establish an employee session. See
[the edge boundary](cloudflare-access.md).

After confirming a real administrator login, an operator may disable shared
password login with `PASSWORD_LOGIN_ENABLED=false`. Preserve `SESSION_SECRET`,
`ENCRYPTION_KEY` and existing data; do not rotate them as part of consolidation.
Shared passwords do not identify an individual for personal data access.

Every existing-product sign-in method records the same governance audit events as
organization OpenID Connect below: `sign_in.succeeded` (with `enrolled` on a
first sign-in), `sign_in.refused` with a fixed reason, and `sign_in.signed_out`.
The resource is the method (`google`, `cloudflare`, `password`) or the OpenID
Connect provider. Google records `cancelled`, `token`, `deactivated`,
`mapping_review` or `unavailable` after a consumed sign-in attempt, and nothing
for an unknown or expired one. A refusal names the person once the provider has
verified them; before that its actor is `anonymous`, and Google and OpenID
Connect keep an anonymous refusal once per client network, reason and minute.
A wrong shared password records `invalid_password` with the actor `anonymous`
(sign-in rate limits bound these); a password sign-in's actor is the shared
account (`Shared password admin` or `member`), never the password. Cloudflare
Access records a sign-in when it issues a new session cookie, at most once per
person and minute, so a client that never keeps cookies cannot flood the audit;
a mapping that needs review or a deactivated person records a refusal, also once
per minute. Each process writes such an event once and then only reads, because
the mapping is checked on every request. A sign-out is recorded once per
session: signing out deletes the cookie, and replaying the same cookie records
nothing more. New Google, password
and Access sessions fail closed: if the event cannot be written, no session
cookie is issued (Google redirects to `?signin=failed`, password and Access
sign-in answer 503). Existing sessions keep working. A refusal or sign-out whose
event cannot be written is logged and still refused or signed out.

Authorization is checked at admission and again at model/tool boundaries.
Approval does not override revoked permissions. Personal memory and credentials
remain private to their owner even when a viewer is an administrator. UI tests
use synthetic accounts; validate the actual identity provider during deployment.

## Organization OpenID Connect (Okta, Microsoft Entra ID)

Existing-product mode can also sign people in directly with an OpenID Connect
provider such as Okta or Microsoft Entra ID. Each provider owns an explicit list
of email domains, and those domains sign in only through it: Google sign-in is
no longer offered or accepted for them, and their existing Google sessions end.
SAML-only identity providers still use [Cloudflare Access](cloudflare-access.md).
With `CLOUDFLARE_ACCESS_LOGIN=true`, Access remains authoritative: provider
buttons are hidden and OIDC sessions are not accepted. Configure every runtime
role with the same values; each role validates them, and an OIDC principal's
authority includes its provider.

A provider must be a single-tenant issuer your organization owns, so that its
verified emails are its own accounts. Microsoft's shared `common`,
`organizations` and `consumers` issuers and Google's `https://accounts.google.com`
accept accounts your organization does not own and are refused; Google Workspace
domains use the Google sign-in above, which checks the hosted domain.

| Setting | Value |
| --- | --- |
| `MOYAI_OIDC_PROVIDERS` | JSON list of providers (fields below); contains no secrets |
| `MOYAI_OIDC_CLIENT_SECRETS` | JSON object mapping each provider `id` to its client secret |
| `GOOGLE_ALLOWED_DOMAINS` | All allowed domains, including every provider domain |
| `GOOGLE_ADMIN_EMAILS` | Default administrators, in the allowed domains |

| Provider field | Meaning |
| --- | --- |
| `id` | Lowercase name in URLs, such as `okta`; not `google`, `cloudflare`, `password` or `local` |
| `label` | Button text: "Continue with `label`" |
| `issuer` | Exact issuer from the provider's discovery document; HTTPS (plain HTTP on loopback serves backend tests only) |
| `client_id` | The application's client ID; ID tokens must name it as audience |
| `domains` | Verified email domains this provider owns; disjoint from other providers |
| `scopes` | Default `["openid", "email", "profile"]` |
| `algorithms` | Allowed ID token algorithms: `RS256` (default), `PS256`, `ES256` |
| `email_claim`, `email_verified_claim` | Defaults `email` and `email_verified`; the verified claim must be the boolean `true` |
| `token_auth` | `client_secret_basic` (default) or `client_secret_post` |
| `prompt` | Optional OpenID Connect `prompt`, such as `login` |
| `require_scim_user` | Accept only people with an active SCIM account, at sign-in and on every later request |

Register `PUBLIC_URL/auth/oidc/<id>/callback` as the provider's redirect URI.
Moyai reads the discovery document on first use and requires its issuer to
match exactly. Sign-in uses the authorization code flow with PKCE S256, a nonce
and a state bound to the browser and the provider. The ID token must carry the
issuer, this client as audience (and as authorized party when present), a
current expiry and issue time, a key from the provider's key set, and a verified
email in one of the provider's domains. If the provider advertises RFC 9207, the
callback must name its issuer. No provider token is retained, and a failed
sign-in only returns to the sign-in page.

### Okta

Create an OIDC web application with the authorization code grant, the redirect
URI above and client secret authentication. Use the custom authorization
server's issuer (`https://<org>.okta.com/oauth2/default`) or the org
authorization server's (`https://<org>.okta.com`). Restrict access with
application assignments.

```json
[{"id": "okta", "label": "Okta", "issuer": "https://example.okta.com/oauth2/default",
  "client_id": "0oa...", "domains": ["example.com"]}]
```

### Microsoft Entra ID

Register a single-tenant application ("Accounts in this organizational directory
only") with a web redirect URI and a client secret. Under Token configuration,
add the `email` and `xms_edov` optional ID token claims; Entra does not send
`email_verified`. In the enterprise application, set Assignment required and
assign the people or groups who may sign in. Use the tenant issuer; the shared
`common`, `organizations` and `consumers` issuers are refused.

```json
[{"id": "entra", "label": "Microsoft", "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "<application-id>", "domains": ["example.com"], "email_verified_claim": "xms_edov"}]
```

### Accounts, migration and deprovisioning

The first sign-in links the one existing Google or Access account with the same
verified email, so ownership, private sessions and roles stay with that account,
then pins the provider's issuer and subject to it. People without an account get
one at first sign-in. Because that first link is by email, before enabling a
provider change the email of, or remove, every leftover account of a person who
has left: otherwise someone later given the same address at the provider inherits
its private sessions, personal credentials and memory. Accounts already pinned to
a subject are not inherited; a new subject for their email needs review.

Two candidate accounts, a second subject for the same email, or a changed email
for a pinned subject fail closed for administrator review (`sign_in.refused` with
reason `mapping_review`). There is no review screen yet. After confirming who the
person is, an administrator resolves the review in the database:

- **Changed email:** confirm that no other account uses the new address, then
  update `users.email` and `access_identities.email` together for that issuer and
  subject. Role assignments are by email; review the new address in Users.
  Deleting the binding instead does not restore access.
- **Second subject** (the person's provider account was recreated): delete the
  old subject's `access_identities` row; the next sign-in links the new subject
  to the existing account.
- **Two candidate accounts:** merge them, or change the email of or remove the
  duplicate, so that exactly one account has the address.

Moving a domain to a provider changes its people's authority: running sessions
need fresh authorization, and workflows blocked by the change must be re-enabled
by their owners, as with the Access cutover.

Disabling someone at the provider stops new sign-ins. An existing session lasts
up to 12 hours and their automations keep running, as with Google. Pair the
provider with [SCIM provisioning](enterprise-governance.md#roles-and-provisioning):
deactivation then revokes access immediately, and `require_scim_user` refuses
anyone who is not provisioned and active, including existing sessions and
grants. Changing `require_scim_user` changes the provider's authority, so running
work needs fresh authorization. Group claims do not grant roles; use SCIM group
grants.

The governance audit records `identity_binding.created` when a subject is first
pinned, `sign_in.succeeded` for every sign-in, and `sign_in.refused` with a fixed
reason (`cancelled`, `issuer`, `unavailable`, `token`, `claims`,
`email_unverified`, `domain`, `mapping_review`, `not_provisioned` or
`deactivated`) after a consumed sign-in attempt. Events carry no tokens, codes or
claims; a refusal names the person only after their identity was verified, and
an anonymous refusal is kept once per provider, client network, reason and minute.
