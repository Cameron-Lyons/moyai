"""The native route gate covers every /api operation; exemptions must be explicit."""

from __future__ import annotations

import re
from types import SimpleNamespace

from app.permissions import PERMISSIONS, route_permission
from test_api_contract import _routes

from moyai.openapi_dump import schema_app

# Each needs no catalog permission, or its handler checks one the map cannot express.
UNGATED = {
    ("GET", "/api/auth/config"): "sign-in options before authentication",
    ("POST", "/api/auth/google/start"): "starts sign-in",
    ("POST", "/api/auth/oidc/{provider}/start"): "starts sign-in",
    ("POST", "/api/login"): "starts sign-in",
    ("POST", "/api/logout"): "ends the caller's own sign-in",
    ("GET", "/api/me"): "the caller's own identity and permissions",
    ("GET", "/api/permissions"): "the catalog and the caller's own permissions",
    ("GET", "/api/admin/spend-limits"): "the handler accepts spend.read or spend.manage",
    ("GET", "/api/admin/spend-limits/effective"): "the handler accepts spend.read or spend.manage",
}


def test_every_api_operation_resolves_to_a_catalog_permission():
    unmapped = set()
    with schema_app() as app:
        for route in _routes(app.routes):
            path = getattr(route, "path", "")
            if not path.startswith("/api/"):
                continue
            for method in (getattr(route, "methods", None) or set()) - {"HEAD"}:
                concrete = re.sub(r"\{[^}]+\}", "placeholder", path)
                permission = route_permission(SimpleNamespace(scope={"path": concrete}, method=method))
                if permission is None:
                    unmapped.add((method, path))
                else:
                    assert permission in PERMISSIONS, (method, path, permission)
    assert unmapped - UNGATED.keys() == set(), "Map these routes in app.permissions.route_permission"
    assert UNGATED.keys() - unmapped == set(), "These routes are mapped now; remove them from UNGATED"


def test_api_key_routes_are_mounted_reads_whose_gate_matches_the_key_ceiling():
    from app.permissions import API_KEY_ROUTES, SERVICE_PERMISSIONS

    with schema_app() as app:
        mounted = {(method, route.path) for route in _routes(app.routes)
                   for method in (getattr(route, "methods", None) or set())}
        # An Authorization header is not ambient, so skipping CSRF for keys
        # relies on no other origin being allowed to send one.
        assert not any("cors" in middleware.cls.__name__.lower() for middleware in app.user_middleware)
    assert set(API_KEY_ROUTES) <= mounted
    assert set(API_KEY_ROUTES.values()) == SERVICE_PERMISSIONS
    for (method, path), permission in API_KEY_ROUTES.items():
        assert method == "GET" and "{" not in path
        assert route_permission(SimpleNamespace(scope={"path": path}, method=method)) == permission


def test_service_account_administration_needs_its_own_permission():
    with schema_app() as app:
        operations = {(method, route.path) for route in _routes(app.routes)
                      if route.path.startswith("/api/admin/service-accounts")
                      for method in (getattr(route, "methods", None) or set())}
    assert operations == {
        ("GET", "/api/admin/service-accounts"), ("POST", "/api/admin/service-accounts"),
        ("PUT", "/api/admin/service-accounts/{identity}"), ("DELETE", "/api/admin/service-accounts/{identity}"),
        ("POST", "/api/admin/service-accounts/{identity}/keys"),
        ("DELETE", "/api/admin/service-accounts/{identity}/keys/{key_id}"),
    }
    for method, path in operations:
        concrete = re.sub(r"\{[^}]+\}", "placeholder", path)
        assert route_permission(SimpleNamespace(scope={"path": concrete}, method=method)) == "service_accounts.manage"
