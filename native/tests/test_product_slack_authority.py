"""Real canonical identity adapter: Slack grants never become browser cookies."""

import json
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from app.connection_authority import refresh_connection
from fastapi import HTTPException, Request
from test_product_secrets import bridge as canonical_bridge
from test_product_secrets import secrets_api as canonical_secrets_api

from moyai.product_slack import ProductSlackAuthority

bridge = canonical_bridge
secrets_api = canonical_secrets_api


def request(cookie):
    return Request({
        "type": "http", "method": "GET", "scheme": "http", "path": "/api/me", "query_string": b"",
        "server": ("127.0.0.1", 8787), "headers": [
            (b"cookie", b"workspace_session=" + cookie.encode()),
            (b"x-slack-user-id", b"UTEST0001"),
        ],
    })


async def enroll(api):
    settings = api.bridge.settings
    settings.slack_bot_enabled = True
    settings.slack_session_users = "UTEST0001"
    settings.slack_signing_secret = "local-signature"
    api.bridge.connectors.save("slack", {
        "access_token": "local-user-token", "bot": {
            "access_token": "local-bot-token", "bot_user_id": "UBOT00001", "team": {"id": "TTEST0001"},
        },
    }, "Local installation")
    with api.bridge.store.connect() as conn:
        identity = api.bridge.store.slack_identity_in(conn, "TTEST0001", "UTEST0001")
    api.identity.slack_authority = ProductSlackAuthority(api.identity)
    return identity


async def test_live_slack_authority_retains_epoch_across_refresh_but_rejects_revocation(secrets_api):
    api = secrets_api
    identity = await enroll(api)
    principal = await api.identity.current(identity)
    assert not principal.individual and principal.method == "slack" and principal.role == "member"
    row = api.bridge.store.rows("SELECT * FROM connections WHERE provider='slack'")[0]
    credentials = json.loads(api.bridge.security.decrypt(row["encrypted"]))
    credentials["bot"]["access_token"] = "local-refreshed-token"
    refresh_connection(api.bridge.store, api.bridge.security, "slack", row, credentials)
    assert (await api.identity.require_current(principal.grant)).grant == principal.grant
    api.bridge.connectors.save("slack", credentials, "Reauthorized")
    with pytest.raises(HTTPException):
        await api.identity.require_current(principal.grant)


async def test_signed_slack_cookie_and_unsigned_identity_headers_cannot_authenticate_browser(secrets_api):
    api = secrets_api
    identity = await enroll(api)
    assert (await api.identity.current(identity)).kind == "slack"
    cookie = api.bridge.security.signer.dumps({
        "sid": secrets.token_urlsafe(20), "method": "slack", "role": "admin",
        "identity": {"sub": "UTEST0001", "email": "admin@example.test", "team_id": "TTEST0001"},
    })
    for value in ("", cookie):
        with pytest.raises(HTTPException) as error:
            await api.identity.authenticate(request(value))
        assert error.value.status_code == 401


@pytest.mark.parametrize("change", ["unlinked", "unavailable", "manual", "foreign"])
async def test_unverified_slack_senders_hold_no_permissions(secrets_api, change):
    """As in canonical actor checks, a sender without a verified, eligible email is never a member."""
    api = secrets_api
    identity = await enroll(api)
    if change == "unavailable":
        api.bridge.store.execute("UPDATE users SET link_status='unavailable',profile_eligible=0 WHERE id=?", (identity,))
    elif change == "manual":
        api.bridge.store.execute(
            "UPDATE users SET link_status='manual',linked_user_id='google:owner' WHERE id=?", (identity,),
        )
    elif change == "foreign":
        api.bridge.store.execute(
            "UPDATE users SET email='sender@elsewhere.test',profile_eligible=1,link_status='linked' WHERE id=?",
            (identity,),
        )
    principal = await api.identity.current(identity)
    assert principal.kind == "slack" and principal.effective_permissions == frozenset()
    # ProductGovernance.principal and every governed admission require this first.
    with pytest.raises(HTTPException) as denied:
        principal.require("sessions.create")
    assert denied.value.status_code == 403


async def test_slack_intake_without_identity_linking_never_verifies_the_sender(secrets_api, monkeypatch):
    """With linking disabled, intake skips the profile lookup, so the sender stays unverified and is refused."""
    from app.permissions import MEMBER_PERMISSIONS

    from moyai.product_slack import ProductSlack
    api = secrets_api
    await enroll(api)
    api.bridge.connectors.save("slack", {
        "access_token": "local-user-token", "bot": {
            "access_token": "local-bot-token", "bot_user_id": "UBOT00001", "team": {"id": "TTEST0001"},
            "scope": "users:read,users:read.email",
        },
    }, "Local installation")

    async def profile(method, url, **kwargs):
        assert url.endswith("/users.info") and kwargs["params"] == {"user": "UTEST0001"}
        return {"ok": True, "user": {"id": "UTEST0001", "team_id": "TTEST0001",
                "profile": {"email": "owner@example.test", "real_name": "Verified owner"}}}

    monkeypatch.setattr(api.bridge.connectors, "request", profile)
    api.runtime.product_connections = api.bridge
    slack = ProductSlack(api.runtime)
    api.bridge.settings.slack_identity_linking_enabled = False
    _, principal = await slack.actor("TTEST0001", "UTEST0001", refresh_profile=True)
    assert principal.kind == "slack" and principal.effective_permissions == frozenset()
    with pytest.raises(HTTPException) as denied:
        principal.require("sessions.create")
    assert denied.value.status_code == 403
    # The same intake with linking enabled verifies the in-domain profile.
    api.bridge.settings.slack_identity_linking_enabled = True
    _, principal = await slack.actor("TTEST0001", "UTEST0001", refresh_profile=True)
    assert principal.effective_permissions == MEMBER_PERMISSIONS


async def test_verified_slack_sender_follows_directory_state(secrets_api):
    from app.permissions import MEMBER_PERMISSIONS
    api = secrets_api
    identity = await enroll(api)
    api.bridge.store.execute(
        "UPDATE users SET email='owner@example.test',profile_eligible=1,link_status='linked' WHERE id=?", (identity,),
    )
    assert (await api.identity.current(identity)).effective_permissions == MEMBER_PERMISSIONS
    # A SCIM tombstone for the verified email revokes the sender outright.
    api.bridge.store.execute(
        "INSERT INTO scim_users(id,user_name,profile,active,deleted_at,created_at,updated_at,revision,access_epoch) "
        "VALUES(?,?,'{}',1,?,?,?,1,1)",
        ("0" * 32, "owner@example.test", "2026-10-20", "2026-10-01", "2026-10-20"),
    )
    with pytest.raises(HTTPException) as denied:
        await api.identity.current(identity)
    assert denied.value.status_code == 401


@pytest.mark.parametrize("change", ["allowlist", "disabled", "profile", "native_epoch"])
async def test_slack_authority_checks_live_source_and_native_controls(secrets_api, change):
    api = secrets_api
    identity = await enroll(api)
    principal = await api.identity.current(identity)
    async with api.runtime.database.sessions.begin() as db:
        actor = await api.identity.project_native_user(db, principal)
    if change == "allowlist":
        api.bridge.settings.slack_session_users = "UOTHER001"
    elif change == "disabled":
        api.bridge.store.execute(
            "INSERT INTO connection_policies(provider,enabled,read_only) VALUES('slack',0,0) "
            "ON CONFLICT(provider) DO UPDATE SET enabled=0",
        )
    elif change == "profile":
        api.bridge.store.execute("UPDATE users SET profile_conflict=1 WHERE id=?", (identity,))
    else:
        async with api.runtime.database.sessions.begin() as db:
            current = await db.get(type(actor), actor.id)
            current.auth_version += 1
    with pytest.raises(HTTPException):
        await api.identity.require_current(principal.grant)


@pytest.mark.parametrize("change", ["fresh", "stale", "conflict", "ambiguous", "owner_disabled"])
async def test_personal_memory_relationship_requires_fresh_unique_verified_owner(secrets_api, change):
    api = secrets_api
    identity = await enroll(api)
    checked = datetime.now(UTC) - timedelta(hours=2 if change == "stale" else 0)
    api.bridge.store.execute(
        """UPDATE users SET email='owner@example.test',profile_eligible=1,profile_checked_at=?,
           profile_conflict=?,link_status='linked' WHERE id=?""",
        (checked.isoformat(), int(change == "conflict"), identity),
    )
    if change == "ambiguous":
        api.bridge.store.execute(
            "INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("google:other", "google", "owner@example.test", "Other", "c", "u"),
        )
    if change == "owner_disabled":
        api.bridge.store.execute(
            "CREATE TABLE moyai_users(id TEXT PRIMARY KEY,enabled BOOLEAN,auth_version INTEGER)",
        )
        api.bridge.store.execute("INSERT INTO moyai_users VALUES('google:owner',0,1)")
    async with api.identity._reader(api.identity.source_engine) as db:
        owner = await api.identity.personal_memory_owner(db, identity)
    assert owner == ("google:owner" if change == "fresh" else None)


@pytest.mark.parametrize('failure', [
    'timeout', 'transport', 'rate-limit', 'invalid_refresh_token', 'token_revoked', 'invalid_auth',
    'missing_scope', 'database',
])
async def test_transient_profile_failures_preserve_the_verified_observation(secrets_api, monkeypatch, failure):
    import httpx
    from app.connector_errors import ConnectorError
    from app.identities import SlackIdentities
    api = secrets_api
    identity = await enroll(api)
    api.bridge.store.execute("UPDATE users SET profile_eligible=1,link_status='linked' WHERE id=?", (identity,))
    row = api.bridge.store.rows('SELECT * FROM users WHERE id=?', (identity,))[0]
    service = SlackIdentities(api.bridge.store, api.bridge.connectors, api.bridge.settings,
                              api.bridge.security, None, lambda *_: False)
    monkeypatch.setattr(service, 'status', lambda: {'ready': True, 'team_id': 'TTEST0001'})
    async def failed(*args, **kwargs):
        if failure == 'timeout':
            raise TimeoutError()
        if failure == 'transport':
            raise httpx.ConnectError('synthetic provider unavailable')
        if failure == 'database':
            from app.database import DatabaseBusyError
            raise DatabaseBusyError('synthetic database unavailable')
        if failure == 'missing_scope':
            return {'ok': False, 'error': 'missing_scope'}
        if failure in {'invalid_refresh_token', 'token_revoked', 'invalid_auth'}:
            raise ConnectorError('synthetic connection failure', code=failure)
        return {'ok': False, 'error': 'ratelimited'}
    monkeypatch.setattr(api.bridge.connectors, 'request', failed)
    with pytest.raises(ConnectorError) as error:
        await service.resolve(row, 'TTEST0001')
    assert error.value.retryable
    assert api.bridge.store.rows('SELECT * FROM users WHERE id=?', (identity,))[0] == row
