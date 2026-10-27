"""Product sign-in and canonical user roles around the new execution core."""

from __future__ import annotations

import asyncio
import hmac
import logging
from typing import TYPE_CHECKING, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .models import User

if TYPE_CHECKING:
    from .runtime import Runtime

log = logging.getLogger(__name__)


class RoleEdit(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    role: Literal["admin", "member"]
    revision: int = Field(ge=0)
    replace_custom_role: bool = False
    access_revision: int | None = Field(default=None, ge=0)


_OUTPUT = ConfigDict(json_schema_serialization_defaults_required=True)


class ProductUserRoleResult(BaseModel):
    model_config = _OUTPUT
    email: str
    role: Literal["admin", "member"]
    revision: int


class ProductAccessRole(BaseModel):
    model_config = _OUTPUT
    id: str
    name: str
    revision: int


class ProductDirectoryUser(BaseModel):
    model_config = _OUTPUT
    id: str
    username: str
    display_name: str
    enabled: bool
    email: str
    name: str | None
    has_signed_in: bool
    last_seen: str | None
    role: str
    revision: int
    # Custom role (None for built-in access) and SCIM state.
    access_role: ProductAccessRole | None
    active: bool
    permissions: list[str]


class ProductRoleActivity(BaseModel):
    model_config = _OUTPUT
    email: str
    previous_role: str
    role: str
    actor: str
    created_at: str


class ProductDirectoryCapabilities(BaseModel):
    model_config = _OUTPUT
    read: bool
    create: bool
    update: bool
    delete: bool
    roles: bool


class ProductUserDirectory(BaseModel):
    model_config = _OUTPUT
    users: list[ProductDirectoryUser]
    activity: list[ProductRoleActivity]
    domains: list[str]
    source: Literal["product"]
    capabilities: ProductDirectoryCapabilities
    note: str


async def user_directory(runtime: Runtime) -> ProductUserDirectory:
    """GET /api/settings/users in product mode; settings_api owns the route."""
    product = runtime.product
    assert product is not None
    directory = await asyncio.to_thread(product.roles.directory)
    return ProductUserDirectory.model_validate({
        **directory,
        "users": [{
            **row, "id": row["email"], "username": row["email"],
            "display_name": row["name"] or row["email"], "enabled": True,
        } for row in directory["users"]],
        "source": "product", "capabilities": {
            "read": True, "create": False, "update": False, "delete": False, "roles": True,
        },
        "note": "Organization sign-in manages accounts. Roles are shared with existing Moyai.",
    })


async def password_login(runtime: Runtime, password: str, request: Request, response: Response):
    product = runtime.product
    assert product is not None
    settings, security = product.settings, product.security
    security.check_origin(request)
    if settings.cloudflare_access_login or not settings.password_login_enabled:
        raise HTTPException(403, "Use your organization sign-in.")
    await runtime.database.limit_login(security.client_key(request), "product-password")
    if settings.workspace_password and hmac.compare_digest(password, settings.workspace_password):
        role = "admin"
    elif settings.workspace_member_password and hmac.compare_digest(password, settings.workspace_member_password):
        role = "member"
    else:
        from app import sign_in_audit
        try:
            # limit_login bounds these writes per client and in total.
            await asyncio.to_thread(sign_in_audit.record, product.store, "sign_in.refused", "anonymous",
                                    "password", reason="invalid_password")
        except Exception as failure:  # noqa: BLE001 - the refusal stands whether or not it is recorded.
            log.warning("Password sign-in refusal was not recorded: %s", type(failure).__name__)
        raise HTTPException(401, "Incorrect workspace password.")
    # Only a verified existing authentication path creates/refreshes canonical
    # account rows. Native user projection never enrolls product accounts. The
    # sign-in event commits with that refresh: without it, no session is issued.
    from app.database import DatabaseError
    try:
        await asyncio.to_thread(product.store.identity, {"method": "password", "role": role}, sign_in=True)
    except DatabaseError:
        raise HTTPException(503, "Sign-in is temporarily unavailable. Try again shortly.") from None
    sid = security.new_session(response, role)
    return {"csrf": security.csrf(sid), "authenticated": True, "role": role}


async def record_sign_out(product, principal) -> None:
    """Record sign_in.signed_out once per organization or shared password session.

    Logout only deletes the cookie, and the signed cookie stays valid until it
    expires, so the event is keyed by the session (its CSRF token, an HMAC of
    the session id): replaying one cookie records one sign-out. Other methods
    (local preview) record nothing. Signing out never depends on the event: a
    lost event is logged, not raised.
    """
    from app import sign_in_audit
    if principal.method not in sign_in_audit.METHODS or not principal.csrf_token:
        return
    from app.enterprise_roles import actor_label
    provider = product.settings.oidc_provider_for_domain(principal.email.rpartition("@")[2]) \
        if principal.method == "oidc" else None
    try:
        await asyncio.to_thread(
            sign_in_audit.record, product.store, "sign_in.signed_out", actor_label(principal), principal.method,
            resource_id=provider.id if provider else None, key=principal.csrf_token,
        )
    except Exception as failure:  # noqa: BLE001 - a lost sign-out event never keeps the session.
        log.warning("Sign-out was not recorded: %s", type(failure).__name__)


def routes(runtime: Runtime, actor) -> APIRouter:
    product = runtime.product
    assert product is not None
    router = APIRouter()
    router.include_router(product.google.routes())
    router.include_router(product.oidc.routes())

    @router.put("/api/settings/users/role", operation_id="updateProductUserRole")
    async def role(body: RoleEdit, request: Request, user: User = Depends(actor)) -> ProductUserRoleResult:
        from .product_governance import permission_for_user
        if not permission_for_user(user, 'users.manage'):
            raise HTTPException(403, "An organization administrator must perform this action.")
        from app.enterprise_roles import GovernanceActor
        from app.user_roles import RoleChange
        # Reuse the product's optimistic revision, last-admin protection, audit,
        # and writer lock. The handler rechecks the authenticated principal
        # inside that transaction, off the event loop.
        result = await asyncio.to_thread(
            product.roles.change, RoleChange(**body.model_dump()),
            GovernanceActor.from_principal(request.state.product_principal),
        )
        return ProductUserRoleResult.model_validate(result)

    return router
