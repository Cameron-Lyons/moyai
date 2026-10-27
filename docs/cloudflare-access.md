# Cloudflare Access boundary

Existing-product mode retains Moyai's canonical Cloudflare Access verification
and optional employee identity handoff. Preserve the deployed tunnel, routing,
audiences and provider policies when upgrading the runtime. The application
release does not provision Cloudflare resources or move the origin.

Employees reach Access, then the existing tunnel and private API origin. Moyai
verifies the signed `Cf-Access-Jwt-Assertion` at the origin; the tunnel alone is
not identity verification. The private origin must not have a public bypass.
Keep its configured public HTTPS origin in `MOYAI_PUBLIC_URL`.

| Setting | Purpose |
| --- | --- |
| `CLOUDFLARE_ACCESS_TEAM_DOMAIN` | Trusted team's issuer and signing-key source |
| `CLOUDFLARE_ACCESS_AUDIENCE` | Employee application audience |
| `CLOUDFLARE_ACCESS_BROKER_AUDIENCE` | Separate machine/broker audience |
| `CLOUDFLARE_ACCESS_CLIENT_ID`, `CLOUDFLARE_ACCESS_CLIENT_SECRET` | Existing machine service credential |
| `CLOUDFLARE_ACCESS_LOGIN` | Optional verified employee identity handoff |
| `TUNNEL_TOKEN` | Connector credential, on the tunnel service only |

Retain the company identity-provider restriction and allowed-domain policy.
Machine assertions cannot become employee accounts. With identity handoff,
Moyai preserves an unambiguous existing account and pins the verified issuer and
subject. Conflicting identities fail closed. Saved roles remain authoritative;
CSRF, current authorization and session visibility checks still apply.

Keep webhook exceptions exact. Existing-product Slack retains `/hooks/slack`,
`/hooks/slack/events` and `/hooks/slack/interactions`; requests still require
Slack signature verification. Automation exceptions apply only to configured
individual webhook paths. Never bypass Access for all `/api/*` or `/hooks/*`.
Provider OAuth callbacks and all new paths need their actual deployed policies.
API key reads have [their own exact exception](#api-keys-and-the-access-edge).

During the maintenance release, preserve both source and candidate routing.
After activation verify an approved employee reaches the same account, a missing
or wrong-audience assertion is rejected, an unapproved identity is blocked,
and historical sessions and authorized downloads still open. Verify webhook
and machine callers independently of browser login. A valid browser session
does not prove service-token routing.

The local product authentication suite uses synthetic signed identities. It does
not certify a live Cloudflare policy or tunnel. Managed application upgrade
runbooks are maintained in a private repository. Follow Cloudflare's
[Access documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/)
for edge changes. Rotate connector and application service credentials separately;
do not regenerate product encryption keys when rotating edge credentials.

## API keys and the Access edge

[Service account API keys](enterprise-governance.md#service-accounts-and-api-keys)
are for collectors that cannot complete an Access sign-in. The origin exempts a
request from its Access check only when both hold:

- the method and path are exactly `GET /api/admin/governance/audit`,
  `GET /api/admin/governance/audit/export` or `GET /api/admin/spend` (no
  prefixes, trailing slashes or other methods), and
- the request carries an `Authorization` header with a Moyai API key
  (`moyai_sk_`), which must then verify.

The same paths without a key keep the employee Access check, and any other
request that carries a key is refused with 403 before Access is consulted. This is
the same kind of application-layer exemption SCIM provisioning uses for
`/scim/v2`.

The origin exemption cannot see requests that Access blocks at the edge, so a
collector also needs an edge policy. Add a **Service Auth** policy that admits one
dedicated Cloudflare service token to the existing Moyai employee application,
keeping its employee policies, and have the collector send that token's
`CF-Access-Client-Id` and `CF-Access-Client-Secret` headers with its Moyai key.
The service token is then a second credential, enforced at the edge.

- Do not use a Bypass policy, and never exempt all of `/api/*` or `/api/admin/*`.
- Do not put these paths in a separate Access application. Employees use the
  audit paths from the Audit log page, and a separate application's assertions
  carry its own audience, which the origin rejects for them.
- The policy admits the token to the whole application at the edge, but the
  origin accepts it only with a valid key on the three operations above; machine
  assertions never become employee sign-ins.
- The origin does not yet verify the service token's own assertion for key
  requests; the Moyai key is the origin credential.

Rotate the service token and the Moyai key independently, and revoke both when a
collector is retired.

## Local Modal connections through WARP

Modal command routers use public names under `*.w.modal.host`. WARP's default
Local Domain Fallback list includes `host`, which also matches these names.
Those queries use the configured fallback DNS servers instead of Gateway DNS.
If those servers are unreachable, sandbox creation can succeed while its first
command fails to resolve the router.

Check `warp-cli dns fallback list` and `warp-cli dns default-fallbacks`, then
compare a live sandbox router's system DNS lookup with a public DNS lookup.
An administrator should review whether the active device profile needs the
broad `host` fallback. Removing it routes these public names through Gateway;
retain more specific fallback entries for any required internal names.
This is a device-profile change, separate from Moyai's Access authentication.
See Cloudflare's [Local Domain Fallback documentation](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/local-domains/).
