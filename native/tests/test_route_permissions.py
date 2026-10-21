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
    ("POST", "/api/login"): "starts sign-in",
    ("POST", "/api/logout"): "ends the caller's own sign-in",
    ("GET", "/api/me"): "the caller's own identity and permissions",
    ("GET", "/api/permissions"): "the catalog and the caller's own permissions",
    ("GET", "/api/admin/spend-limits"): "the handler accepts spend.read or spend.manage",
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
