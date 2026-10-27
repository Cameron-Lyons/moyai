"""Product password sign-in, sign-out and Access sign-in failures in the governance audit.

The canonical Store runs on SQLite; no PostgreSQL or identity provider is needed.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from app import sign_in_audit
from app.config import Settings as ProductSettings
from app.database import DatabaseError
from app.db import Store
from app.schema_migrations import initialize_components
from app.security import Security
from app.user_roles import UserRoles
from cryptography.fernet import Fernet
from fastapi import HTTPException, Response
from starlette.requests import Request

from moyai.product_access import access_session
from moyai.product_auth import password_login, record_sign_out

ORIGIN = "http://127.0.0.1:8787"
PASSWORD = "administrator-password-1"


@pytest.fixture
def product(tmp_path):
    settings = ProductSettings(
        _env_file=None, data_dir=tmp_path, public_url=ORIGIN, session_secret="synthetic-session-secret",
        encryption_key=Fernet.generate_key().decode(), workspace_password=PASSWORD,
    )
    store = Store(tmp_path)
    initialize_components(store)
    try:
        yield SimpleNamespace(settings=settings, store=store, security=Security(settings, UserRoles(store, settings)))
    finally:
        store.close()


def runtime_for(product):
    async def limit_login(network, label):
        return None

    return SimpleNamespace(product=product, database=SimpleNamespace(limit_login=limit_login))


def login_request():
    return Request({"type": "http", "method": "POST", "path": "/api/login", "query_string": b"", "state": {},
                    "headers": [(b"origin", ORIGIN.encode())], "client": ("203.0.113.9", 4321)})


def sign_ins(product):
    rows = product.store.rows("SELECT action,actor,resource_id,details FROM governance_audit_events "
                              "WHERE resource_type='sign_in' ORDER BY created_at,id")
    return [(row["action"], row["actor"], row["resource_id"], json.loads(row["details"])) for row in rows]


async def test_password_sign_in_records_success_and_refusal_without_the_password(product):
    runtime = runtime_for(product)
    with pytest.raises(HTTPException) as refused:
        await password_login(runtime, "wrong-password-" + PASSWORD, login_request(), Response())
    assert (refused.value.status_code, refused.value.detail) == (401, "Incorrect workspace password.")
    for _ in range(2):
        response = Response()
        assert (await password_login(runtime, PASSWORD, login_request(), response))["authenticated"]
        assert "workspace_session=" in response.headers["set-cookie"]
    assert sign_ins(product) == [
        ("sign_in.refused", "anonymous", "password", {"method": "password", "reason": "invalid_password"}),
        ("sign_in.succeeded", "Shared password admin", "password", {"method": "password", "enrolled": True}),
        ("sign_in.succeeded", "Shared password admin", "password", {"method": "password", "enrolled": False}),
    ]
    assert PASSWORD not in json.dumps(product.store.rows("SELECT * FROM governance_audit_events"))


async def test_password_sign_in_issues_no_session_without_its_event(product, monkeypatch):
    def failing(*args, **kwargs):
        raise DatabaseError("synthetic audit failure")

    monkeypatch.setattr(sign_in_audit, "succeeded_in", failing)
    response = Response()
    with pytest.raises(HTTPException) as unavailable:
        await password_login(runtime_for(product), PASSWORD, login_request(), response)
    assert unavailable.value.status_code == 503 and "set-cookie" not in response.headers
    # The account refresh rolled back with its event.
    assert not product.store.rows("SELECT 1 FROM users") and not sign_ins(product)


async def test_a_lost_refusal_event_still_refuses(product, monkeypatch, caplog):
    def failing(*args, **kwargs):
        raise DatabaseError("synthetic audit failure")

    monkeypatch.setattr(sign_in_audit, "record", failing)
    with caplog.at_level("WARNING", logger="moyai.product_auth"), pytest.raises(HTTPException) as refused:
        await password_login(runtime_for(product), "wrong-password-value", login_request(), Response())
    assert refused.value.status_code == 401 and "DatabaseError" in caplog.text


async def test_sign_out_is_recorded_per_method_and_session_and_never_blocks_signing_out(
        product, monkeypatch, caplog):
    okta = SimpleNamespace(id="okta")
    resources = SimpleNamespace(store=product.store, settings=SimpleNamespace(
        oidc_provider_for_domain=lambda domain: okta if domain == "example.test" else None))
    person = {"id": "oidc:subject", "email": "person@example.test", "individual": True}
    shared = {"email": "", "individual": False}
    with caplog.at_level("WARNING", logger="moyai.product_auth"):
        await record_sign_out(resources, SimpleNamespace(method="oidc", csrf_token="session-1", **person))
        for _ in range(2):  # A replayed cookie is the same session.
            await record_sign_out(resources, SimpleNamespace(
                method="google", csrf_token="session-2", **{**person, "id": "google:subject"}))
        await record_sign_out(resources, SimpleNamespace(
            method="password", id="shared:password:member", csrf_token="session-3", **shared))
        # Local preview, other methods and a principal without a session record nothing, quietly.
        await record_sign_out(resources, SimpleNamespace(
            method="local", id="shared:local:admin", csrf_token="session-4", **shared))
        await record_sign_out(resources, SimpleNamespace(
            method="slack", id="slack:team:user", csrf_token="session-5", **shared))
        await record_sign_out(resources, SimpleNamespace(method="google", csrf_token="", **person))
    assert sign_ins(product) == [
        ("sign_in.signed_out", "person@example.test", "okta", {"method": "oidc"}),
        ("sign_in.signed_out", "person@example.test", "google", {"method": "google"}),
        ("sign_in.signed_out", "Shared password member", "password", {"method": "password"}),
    ]
    assert not caplog.text
    # The session's CSRF token only keys the event; it is never stored.
    assert "session-2" not in json.dumps(product.store.rows("SELECT * FROM governance_audit_events"))

    def failing(*args, **kwargs):
        raise DatabaseError("synthetic audit failure")

    monkeypatch.setattr(sign_in_audit, "record", failing)
    with caplog.at_level("WARNING", logger="moyai.product_auth"):
        await record_sign_out(resources, SimpleNamespace(method="google", csrf_token="session-6", **person))
    assert "Sign-out was not recorded: DatabaseError" in caplog.text and "person@example.test" not in caplog.text


async def test_logout_route_records_one_sign_out_per_session(tmp_path, runtime):
    """Logout only deletes the cookie, so replaying the still-valid cookie must not add events."""
    import httpx
    from fastapi import APIRouter
    from sqlalchemy.ext.asyncio import create_async_engine
    from test_product_identity import google_cookie, settings_for

    from moyai.api import create_app
    from moyai.product_identity import ProductIdentityAdapter

    (tmp_path / "canonical").mkdir()
    store = Store(tmp_path / "canonical")
    initialize_components(store)
    store.execute("INSERT INTO users(id,kind,email,name,created_at,updated_at) "
                  "VALUES('google:admin-sub','google','admin@example.test','Product admin','c','u')")
    settings = settings_for(tmp_path)
    source = create_async_engine(f"sqlite+aiosqlite:///file:{store.path}?mode=ro&uri=true")
    adapter = ProductIdentityAdapter(settings, source)
    resources = SimpleNamespace(
        settings=settings, identity=adapter, store=store, scim=SimpleNamespace(router=APIRouter),
        google=SimpleNamespace(routes=APIRouter), oidc=SimpleNamespace(routes=APIRouter),
    )
    sessions = [google_cookie(adapter), google_cookie(adapter)]
    try:
        with pytest.MonkeyPatch.context() as patch:
            # Restore the runtime's product before the runtime fixture closes it.
            patch.setattr(runtime, "product", resources)
            patch.setattr(runtime, "product_identity", adapter)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(runtime, run_dispatcher=False)),
                base_url=settings.public_url, headers={"origin": settings.public_url},
            ) as client:
                for cookie, csrf in (*sessions, sessions[0]):
                    client.cookies.set("workspace_session", cookie)
                    response = await client.post("/api/logout", headers={"x-csrf-token": csrf})
                    assert response.status_code == 200, response.text
                    assert response.json()["signed_out"] and "workspace_session=" in response.headers["set-cookie"]
        rows = store.rows("SELECT action,actor,resource_id,details FROM governance_audit_events "
                          "WHERE resource_type='sign_in' ORDER BY created_at,id")
        assert [(row["action"], row["actor"], row["resource_id"], json.loads(row["details"])) for row in rows] == [
            ("sign_in.signed_out", "admin@example.test", "google", {"method": "google"})] * 2
    finally:
        await source.dispose()
        store.close()


async def test_access_sign_in_database_failures_are_unavailable_not_errors():
    async def check(path, method, assertion):
        return {"sub": "subject", "issuer": "https://synthetic.cloudflareaccess.com",
                "email": "person@example.test", "domain": "example.test"}

    def failing(request, identity):
        raise DatabaseError("synthetic enrollment or audit failure")

    resources = SimpleNamespace(settings=SimpleNamespace(cloudflare_access_login=True),
                                identity=SimpleNamespace(access=SimpleNamespace(check=check)),
                                security=SimpleNamespace(access_session=failing))
    with pytest.raises(HTTPException) as unavailable:
        await access_session(resources, login_request())
    assert (unavailable.value.status_code, unavailable.value.detail) == (
        503, "Organization sign-in is temporarily unavailable.")
