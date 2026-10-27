"""Per-session outbound network allowlists on Modal computers.

A session's effective network_domains is passed to Modal when its computer is
created, never set on a running computer: Modal fixes the allowlist type at
creation, and a computer created open can never be restricted later. null keeps
Modal's open network with no extra arguments, exactly as before; [] and a list
become an allowlist with no CIDR entries (never block_network). Modal matches
TLS SNI on port 443 only, so plain HTTP, SSH and other ports are blocked, while
DNS lookups are not restricted.

The creation-time policy is recorded in an immutable sandbox tag. Every attach
that can lead to an agent or human action compares that tag with the session's
current effective policy and refuses a computer created under a wider one. A
computer without the tag predates this module or is unrestricted, so it counts
as open. Only a digest is tagged, so a computer created under any other
restricted list, even a narrower one, is conservatively refused too.

create_sandbox is the only wrapper around modal.Sandbox.create for session
computers; test_modal_network keeps every other create and attach site listed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import anyio
import modal
from pydantic_ai import RunContext
from pydantic_ai.workspaces import WorkspaceBackend, WorkspaceRef, WorkspaceUnavailableError
from pydantic_ai_harness import ModalSandbox
from pydantic_ai_harness.modal_sandbox import ModalSandboxBackend
from pydantic_ai_harness.modal_sandbox._backend import _CREATE_TIMEOUT, _translate

from .contracts import RunScope
from .product_continuation_errors import preparation_blocked

if TYPE_CHECKING:
    from .database import Database

NETWORK_TAG = "moyai-network"
SESSION_TAG = "moyai-session"
OPEN = "open"
# Arguments only the plan may set on a session computer.
NETWORK_ARGUMENTS = frozenset({
    "block_network", "outbound_domain_allowlist", "outbound_cidr_allowlist", "cidr_allowlist", "tags",
})
TAG_CACHE_SIZE = 4096
MISMATCH = (
    "This computer was started under a different network policy than the session now has. "
    "Start a new chat or let the computer stop; files are kept in its last checkpoint."
)
UNSUPPORTED = "Lambda computers cannot enforce a network allowlist."
logger = logging.getLogger(__name__)


class NetworkPolicyRefused(WorkspaceUnavailableError):
    """The session's network policy refuses this computer; the message is a fixed public sentence."""


class NetworkPolicyMismatch(NetworkPolicyRefused):
    """The computer was created under a wider, or another restricted, policy than the session's current one."""

    def __init__(self):
        super().__init__(MISMATCH)


@dataclass(frozen=True)
class NetworkPlan:
    """The outbound allowlist a session's computer is created and checked under; None is unrestricted."""

    domains: tuple[str, ...] | None
    session_id: str = ""

    @classmethod
    def of(cls, domains, session_id: str = "") -> NetworkPlan:
        return cls(None if domains is None else tuple(sorted(set(domains))), session_id)

    @property
    def digest(self) -> str:
        document = json.dumps({"v": 1, "domains": None if self.domains is None else list(self.domains)},
                              sort_keys=True)
        return hashlib.sha256(document.encode()).hexdigest()[:32]

    @property
    def tag(self) -> str:
        return OPEN if self.domains is None else "d1-" + self.digest


UNRESTRICTED = NetworkPlan(None)


def modal_kwargs(plan: NetworkPlan) -> dict[str, Any]:
    """Sandbox.create arguments for the plan; an unrestricted plan adds none."""
    if plan.domains is None:
        return {}
    return {
        "outbound_domain_allowlist": list(plan.domains),
        "outbound_cidr_allowlist": [],
        "tags": {NETWORK_TAG: plan.tag, SESSION_TAG: plan.session_id},
    }


def compatible(created: str, plan: NetworkPlan) -> bool:
    """Whether a computer created under the tagged policy is within the plan."""
    return plan.domains is None or created == plan.tag


# Tags are fixed at creation (Moyai never calls set_tags), so a read stays valid.
_tags: OrderedDict[str, str] = OrderedDict()


def _remember(sandbox_id: str, tag: str) -> None:
    _tags[sandbox_id] = tag
    _tags.move_to_end(sandbox_id)
    while len(_tags) > TAG_CACHE_SIZE:
        _tags.popitem(last=False)


async def sandbox_network(sandbox: Any) -> str:
    """The network tag the computer was created with; untagged computers are open."""
    tag = _tags.get(sandbox.object_id)
    if tag is None:
        tag = (await sandbox.get_tags.aio()).get(NETWORK_TAG, OPEN)
    _remember(sandbox.object_id, tag)
    return tag


async def network_plan(database: Any, session_id: str) -> NetworkPlan:
    """The session's current plan; unrestricted when nothing is governed. Resolution errors propagate."""
    governance = getattr(database, "governance", None)
    if governance is None:
        return UNRESTRICTED
    return await governance.network_plan(session_id)


async def require_compatible(plan: NetworkPlan, sandbox: Any) -> None:
    """Refuse a computer created under a wider policy than the plan, before anything runs in it."""
    if plan.domains is None:
        return  # Every computer is within an unrestricted plan; no tag read.
    if not compatible(await sandbox_network(sandbox), plan):
        logger.warning("Refused Modal computer %s created under another network policy (session %s).",
                       sandbox.object_id, plan.session_id)
        raise NetworkPolicyMismatch()


async def reusable(plan: NetworkPlan, sandbox: Any) -> Any:
    """require_compatible for preparation, which reports a refusal as a public preparation notice."""
    try:
        await require_compatible(plan, sandbox)
    except NetworkPolicyMismatch as error:
        raise preparation_blocked("workspace_network_policy_changed") from error
    return sandbox


def require_unrestricted(plan: NetworkPlan) -> None:
    """Refuse a restricted plan on a provider that cannot enforce one."""
    if plan.domains is not None:
        raise NetworkPolicyRefused(UNSUPPORTED)


async def create_sandbox(*args: str, plan: NetworkPlan, **kwargs: Any) -> modal.Sandbox:
    """modal.Sandbox.create for a session computer, with the plan's network arguments and tags."""
    if supplied := NETWORK_ARGUMENTS.intersection(kwargs):
        raise TypeError(f"The session network plan sets {', '.join(sorted(supplied))}.")
    sandbox = await modal.Sandbox.create.aio(*args, **kwargs, **modal_kwargs(plan))
    _remember(sandbox.object_id, plan.tag)
    return sandbox


class NetworkGovernor:
    """Resolves one session's plan for a workspace backend; constructed without I/O."""

    def __init__(self, database: Database, session_id: str):
        self.database, self.session_id = database, session_id

    @classmethod
    def of(cls, database: Any, session_id: str) -> NetworkGovernor | None:
        """A governor, or None when the deployment governs nothing (standalone mode)."""
        return cls(database, session_id) if getattr(database, "governance", None) is not None else None

    async def plan(self) -> NetworkPlan:
        return await network_plan(self.database, self.session_id)


class GovernedModalSandboxBackend(ModalSandboxBackend):
    """ModalSandboxBackend that creates under the session's plan and refuses a wider attached computer.

    Without a governor it behaves exactly like the harness backend.
    """

    def __init__(self, *, governor: NetworkGovernor | None = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._governor = governor

    async def _attach(self, sandbox_id: str) -> modal.Sandbox:
        sandbox = await super()._attach(sandbox_id)
        if self._governor is not None:
            await require_compatible(await self._governor.plan(), sandbox)
        return sandbox

    async def _admit(self, sandbox: modal.Sandbox) -> modal.Sandbox:
        """Recheck a created or recovered computer, in case the policy narrowed while it was created."""
        assert self._governor is not None
        try:
            await require_compatible(await self._governor.plan(), sandbox)
        except NetworkPolicyMismatch:
            # Nothing has run in it yet; a retry creates a new one under the current plan.
            self._create_name = None
            try:
                await sandbox.terminate.aio()
            except Exception:  # noqa: BLE001 - the refusal stands; Modal reaps it at its timeout
                logger.warning("Could not terminate refused Modal sandbox %s", sandbox.object_id)
            raise
        return sandbox

    async def _create(self) -> modal.Sandbox:
        """pydantic-ai-harness 0.55.0's ModalSandboxBackend._create under the session's network plan.

        A reviewed copy; test_modal_network pins the harness version and the
        source of the original. Moyai's changes are marked.
        """
        if self._governor is None:
            return await super()._create()
        # Moyai: resolve the plan before any Modal call; a failure creates nothing.
        plan = await self._governor.plan()
        sandbox: modal.Sandbox | None = None
        create_attempted = False
        if self._create_name is None:
            self._create_name = f"pydantic-ai-{uuid4().hex}"
        name = self._create_name
        try:
            # Shielded so that a caller cancelled mid-create still gets the sandbox Modal made:
            # `get_sandbox` records it before the cancellation is delivered, so `ref` names it and
            # a retry reuses it. Only the local deadline interrupts the call; a sandbox created
            # after it fires is reaped at its `sandbox_timeout`.
            with anyio.CancelScope(shield=True), anyio.move_on_after(_CREATE_TIMEOUT):
                app = await modal.App.lookup.aio(self._app_name, create_if_missing=self._create_app_if_missing)
                if self._image is None:
                    # Built on create, not at import: Modal caches it per workspace after the first build.
                    built = modal.Image.debian_slim(python_version="3.12").apt_install("git", "ripgrep")
                elif isinstance(self._image, str):
                    built = modal.Image.from_registry(self._image)  # pyright: ignore[reportUnknownMemberType]
                else:
                    built = self._image
                variables: dict[str, str | None] | None = dict(self._env) if self._env else None
                create_attempted = True
                # Moyai: create_sandbox adds the plan's network arguments and tags.
                sandbox = await create_sandbox(
                    app=app,
                    image=built,
                    name=name,
                    # The default image has no WORKDIR (`/`); start in its user's home, as a login shell would.
                    workdir=self._working_dir or ("/root" if self._image is None else None),
                    env=variables,
                    timeout=self._sandbox_timeout,
                    idle_timeout=self._idle_timeout,
                    plan=plan,
                )
        except Exception as error:
            if create_attempted and (recovered := await self._recover_create(name)) is not None:
                # Moyai: a recovered computer may come from an attempt under another plan.
                return await self._admit(recovered)
            message = f"Could not start Modal sandbox: {error}"
            mapped = _translate(error, context=message, unavailable=message)
            # SDK releases disagree on whether image build errors live in modal.exception.
            if type(error).__name__ == "ImageBuildError":
                raise WorkspaceUnavailableError(message) from error
            if mapped is None:
                raise
            # Modal refused the request itself: an unknown app or image, or an invalid argument
            # such as a `sandbox_timeout` above its limit. Retrying cannot fix that, so it ends
            # the run rather than going back to the model.
            raise (
                mapped if isinstance(mapped, WorkspaceUnavailableError) else WorkspaceUnavailableError(message)
            ) from error
        if sandbox is None:
            if create_attempted and (recovered := await self._recover_create(name)) is not None:
                return await self._admit(recovered)  # Moyai
            # Keep the name across retries, so a late commit can still be recovered.
            raise TimeoutError(
                f"Modal sandbox creation did not complete within {_CREATE_TIMEOUT}s; "
                "an image build or pull may still be running. Check for an existing sandbox before retrying."
            )
        return await self._admit(sandbox)  # Moyai


class GovernedModalSandbox(ModalSandbox[RunScope]):
    """ModalSandbox whose backends create and attach under the run's session network plan.

    get_workspace reads only deps, as durable execution requires, and returns the
    same backend type in the workflow and on the worker.
    """

    def __init__(self, *, database: Database, **kwargs: Any):
        super().__init__(**kwargs)
        self.database = database

    def get_workspace(self, ctx: RunContext[RunScope], *, ref: WorkspaceRef | None) -> WorkspaceBackend | None:
        if ref is not None and ref.provider != "modal":
            return None
        return GovernedModalSandboxBackend(
            ref=ref or self._sandbox_id_ref,
            image=self.image,
            app_name=self.app_name,
            create_app_if_missing=self.create_app_if_missing,
            sandbox_timeout=self.sandbox_timeout,
            idle_timeout=self.idle_timeout,
            working_dir=self.working_dir,
            env=self.env,
            governor=NetworkGovernor.of(self.database, ctx.deps.session_id),
        )
