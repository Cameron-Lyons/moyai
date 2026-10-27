"""Per-session network allowlists on Modal computers; no real Modal calls.

modal_network passes the session's plan at creation and refuses a computer
whose creation-time tag is wider than the current plan. The operator probe in
native/tests/modal_egress_probe.py checks the Modal behavior itself.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import modal
import pytest
from app.security_profiles import CorruptPolicy, OrganizationPolicyUnavailable
from fastapi import HTTPException
from modal._utils.name_utils import check_tag_dict
from modal.sandbox import _build_outbound_network_access
from modal_proto import api_pb2
from pydantic_ai.workspaces import WorkspaceRef, WorkspaceUnavailableError
from pydantic_ai_harness.modal_sandbox import ModalSandbox, ModalSandboxBackend
from temporalio.exceptions import ApplicationError

from moyai import modal_network
from moyai.modal_network import (
    NETWORK_TAG,
    OPEN,
    SESSION_TAG,
    UNRESTRICTED,
    GovernedModalSandbox,
    GovernedModalSandboxBackend,
    NetworkGovernor,
    NetworkPlan,
    NetworkPolicyMismatch,
    NetworkPolicyRefused,
    compatible,
    create_sandbox,
    modal_kwargs,
)

SOURCE = Path(__file__).parents[1] / "src" / "moyai"
SESSION = "3f2b8c1e-0d4a-4f6e-9b7a-2c5d8e1f0a3b"
LISTED = NetworkPlan.of(["a.example.com", "*.b.example.com"], SESSION)
NOTHING = NetworkPlan.of([], SESSION)
ACCESS = api_pb2.NetworkAccess.NetworkAccessType


@pytest.fixture(autouse=True)
def fresh_tags():
    modal_network._tags.clear()
    yield
    modal_network._tags.clear()


class Governor:
    """Returns each plan in turn, then the last one."""

    def __init__(self, *plans):
        self.plans, self.calls = list(plans), 0

    async def plan(self):
        self.calls += 1
        value = self.plans[min(self.calls, len(self.plans)) - 1]
        if isinstance(value, Exception):
            raise value
        return value


def computer(identity="sb-computer", tags=None, *, finished=None):
    process = SimpleNamespace(wait=SimpleNamespace(aio=AsyncMock(return_value=0)))
    return SimpleNamespace(
        object_id=identity,
        get_tags=SimpleNamespace(aio=AsyncMock(return_value=dict(tags or {}))),
        poll=SimpleNamespace(aio=AsyncMock(return_value=finished)),
        terminate=SimpleNamespace(aio=AsyncMock()),
        exec=SimpleNamespace(aio=AsyncMock(return_value=process)),
        create_connect_token=SimpleNamespace(aio=AsyncMock()),
    )


def tagged(plan, identity="sb-computer", **kwargs):
    return computer(identity, {NETWORK_TAG: plan.tag, SESSION_TAG: SESSION}, **kwargs)


def install_modal(monkeypatch, *, created=None, create_error=None, existing=None, attached=None):
    """Fake the Modal SDK entry points modal_network and the harness call."""
    lookup = AsyncMock(return_value=SimpleNamespace(name="app"))
    create = AsyncMock(return_value=created, side_effect=create_error)
    from_name = AsyncMock(return_value=existing, side_effect=None if existing else modal.exception.NotFoundError("no"))
    from_id = AsyncMock(return_value=attached)
    monkeypatch.setattr(modal.App.lookup, "aio", lookup)
    monkeypatch.setattr(modal.Sandbox.create, "aio", create)
    monkeypatch.setattr(modal.Sandbox.from_name, "aio", from_name)
    monkeypatch.setattr(modal.Sandbox.from_id, "aio", from_id)
    return SimpleNamespace(lookup=lookup, create=create, from_name=from_name, from_id=from_id)


@pytest.mark.parametrize(("domains", "expected"), [
    (None, None),
    ([], ()),
    (["a.example.com", "*.b.example.com"], ("*.b.example.com", "a.example.com")),
])
def test_plans_map_to_modal_network_access(domains, expected):
    plan = NetworkPlan.of(domains, SESSION)
    kwargs = modal_kwargs(plan)
    assert "block_network" not in kwargs
    access = _build_outbound_network_access(
        False, kwargs.get("outbound_cidr_allowlist"), kwargs.get("outbound_domain_allowlist"),
    )
    if expected is None:
        # Unrestricted sessions keep Modal's default exactly: no arguments, not even tags.
        assert kwargs == {} and plan.tag == OPEN
        assert access.network_access_type == ACCESS.OPEN
        return
    # [] allows nothing through an empty allowlist, never BLOCKED, which would rule
    # out connect tokens' ports and a later live policy.
    assert access.network_access_type == ACCESS.ALLOWLIST
    assert tuple(access.allowed_domains) == expected and list(access.allowed_cidrs) == []
    assert kwargs["tags"] == {NETWORK_TAG: plan.tag, SESSION_TAG: SESSION}
    check_tag_dict(kwargs["tags"])


def test_plan_digest_is_stable_and_ignores_order_and_session():
    assert LISTED.tag == "d1-" + hashlib.sha256(
        b'{"domains": ["*.b.example.com", "a.example.com"], "v": 1}').hexdigest()[:32]
    assert NetworkPlan.of(["*.b.example.com", "a.example.com", "a.example.com"]).tag == LISTED.tag
    assert NOTHING.tag != LISTED.tag != OPEN


def test_compatibility_refuses_wider_and_different_computers():
    assert compatible(LISTED.tag, LISTED) and compatible(OPEN, UNRESTRICTED) and compatible(LISTED.tag, UNRESTRICTED)
    assert not compatible(OPEN, LISTED) and not compatible(OPEN, NOTHING)
    # Only a digest is tagged, so a different list is refused even when narrower.
    assert not compatible(NOTHING.tag, LISTED) and not compatible(LISTED.tag, NOTHING)


async def test_create_sandbox_owns_every_network_argument(monkeypatch):
    fake = install_modal(monkeypatch, created=computer("sb-new"))
    for argument in ("block_network", "outbound_domain_allowlist", "outbound_cidr_allowlist", "cidr_allowlist", "tags"):
        with pytest.raises(TypeError, match=argument):
            await create_sandbox(app="app", plan=LISTED, **{argument: None})
    fake.create.assert_not_awaited()
    assert await create_sandbox("sleep", "1", app="app", plan=UNRESTRICTED) is fake.create.return_value
    fake.create.assert_awaited_once_with("sleep", "1", app="app")


async def harness_create_kwargs(monkeypatch, backend):
    fake = install_modal(monkeypatch, created=computer("sb-new"))
    await backend.get_sandbox()
    fake.create.assert_awaited_once()
    return fake.create.await_args.kwargs


@pytest.mark.parametrize("plan", [UNRESTRICTED, NOTHING, LISTED])
async def test_governed_create_is_the_harness_create_plus_the_plan(monkeypatch, plan):
    image = modal.Image.debian_slim()
    config = {"image": image, "app_name": "moyai-test", "working_dir": "/workspace", "sandbox_timeout": 3600,
              "idle_timeout": 600, "env": {"LANG": "C.UTF-8"}}
    harness = await harness_create_kwargs(monkeypatch, ModalSandboxBackend(**config))
    governor = Governor(plan)
    backend = GovernedModalSandboxBackend(**config, governor=governor)
    governed = await harness_create_kwargs(monkeypatch, backend)
    assert governed.pop("name").startswith("pydantic-ai-") and harness.pop("name").startswith("pydantic-ai-")
    assert governed == {**harness, **modal_kwargs(plan)}
    assert governed["image"] is image and governed["workdir"] == "/workspace" and governed["timeout"] == 3600
    # Resolved before the create and rechecked after it; the fresh tag needs no read.
    assert governor.calls == 2 and backend.ref == WorkspaceRef(provider="modal", id="sb-new")


async def test_policy_narrowed_during_create_terminates_the_new_computer(monkeypatch):
    created = computer("sb-new")
    fake = install_modal(monkeypatch, created=created)
    backend = GovernedModalSandboxBackend(working_dir="/workspace", governor=Governor(LISTED, NOTHING))
    with pytest.raises(NetworkPolicyMismatch):
        await backend.get_sandbox()
    assert fake.create.await_args.kwargs["outbound_domain_allowlist"] == list(LISTED.domains)
    created.terminate.aio.assert_awaited_once()
    created.exec.aio.assert_not_awaited()
    # A retry creates a new computer under the current plan instead of recovering this one.
    assert backend.ref is None and backend._create_name is None


async def test_widened_policy_keeps_the_new_computer(monkeypatch):
    created = computer("sb-new")
    install_modal(monkeypatch, created=created)
    backend = GovernedModalSandboxBackend(working_dir="/workspace", governor=Governor(LISTED, UNRESTRICTED))
    assert await backend.get_sandbox() is created
    created.terminate.aio.assert_not_awaited()


@pytest.mark.parametrize("tags", [{}, {NETWORK_TAG: OPEN}, {NETWORK_TAG: NOTHING.tag}])
async def test_recovered_create_under_another_policy_is_refused(monkeypatch, tags):
    """A lost create reply is recovered by name; that computer may come from an attempt under another plan."""
    recovered = computer("sb-recovered", tags)
    fake = install_modal(monkeypatch, create_error=modal.exception.AlreadyExistsError("taken"), existing=recovered)
    backend = GovernedModalSandboxBackend(working_dir="/workspace", governor=Governor(LISTED))
    with pytest.raises(NetworkPolicyMismatch):
        await backend.get_sandbox()
    fake.from_name.assert_awaited_once()
    recovered.get_tags.aio.assert_awaited_once()
    recovered.terminate.aio.assert_awaited_once()


async def test_recovered_create_under_the_same_policy_is_kept(monkeypatch):
    recovered = tagged(LISTED, "sb-recovered")
    install_modal(monkeypatch, create_error=modal.exception.AlreadyExistsError("taken"), existing=recovered)
    backend = GovernedModalSandboxBackend(working_dir="/workspace", governor=Governor(LISTED))
    assert await backend.get_sandbox() is recovered
    recovered.terminate.aio.assert_not_awaited()


@pytest.mark.parametrize("failure", [
    RuntimeError("database unavailable"), CorruptPolicy(), OrganizationPolicyUnavailable(),
])
async def test_unresolved_plan_creates_nothing(monkeypatch, failure):
    fake = install_modal(monkeypatch, created=computer("sb-new"))
    backend = GovernedModalSandboxBackend(working_dir="/workspace", governor=Governor(failure))
    with pytest.raises(type(failure)):
        await backend.get_sandbox()
    fake.lookup.assert_not_awaited()
    fake.create.assert_not_awaited()


@pytest.mark.parametrize(("created", "plan", "allowed"), [
    (LISTED, LISTED, True),
    (None, LISTED, False),
    (None, NOTHING, False),
    (LISTED, UNRESTRICTED, True),
    (None, UNRESTRICTED, True),
    (NOTHING, LISTED, False),
])
async def test_attach_compares_the_creation_tag_with_the_current_plan(monkeypatch, created, plan, allowed):
    attached = tagged(created) if created else computer()
    install_modal(monkeypatch, attached=attached)
    backend = GovernedModalSandboxBackend(ref=WorkspaceRef(provider="modal", id="sb-computer"),
                                          working_dir="/workspace", governor=Governor(plan))
    if allowed:
        assert await backend.get_sandbox() is attached
    else:
        with pytest.raises(WorkspaceUnavailableError, match="different network policy"):
            await backend.run(["true"])
        attached.exec.aio.assert_not_awaited()
        # Never terminated: its files and the checkpoint stay for a new chat or restore.
        attached.terminate.aio.assert_not_awaited()
    if plan.domains is None:
        attached.get_tags.aio.assert_not_awaited()


async def test_tags_are_read_once_per_computer_and_the_cache_is_bounded(monkeypatch):
    attached = tagged(LISTED)
    install_modal(monkeypatch, attached=attached)
    for _ in range(3):
        backend = GovernedModalSandboxBackend(ref=WorkspaceRef(provider="modal", id="sb-computer"),
                                              governor=Governor(LISTED))
        await backend.get_sandbox()
    attached.get_tags.aio.assert_awaited_once()
    monkeypatch.setattr(modal_network, "TAG_CACHE_SIZE", 2)
    for identity in ("sb-1", "sb-2", "sb-3"):
        await modal_network.sandbox_network(computer(identity))
    assert list(modal_network._tags) == ["sb-2", "sb-3"]


async def test_ungoverned_backends_are_the_harness(monkeypatch):
    attached, created = computer(), computer("sb-new")
    fake = install_modal(monkeypatch, attached=attached, created=created)
    await GovernedModalSandboxBackend(ref=WorkspaceRef(provider="modal", id="sb-computer")).get_sandbox()
    assert await GovernedModalSandboxBackend().get_sandbox() is created
    assert set(fake.create.await_args.kwargs) == {"app", "image", "name", "workdir", "env", "timeout", "idle_timeout"}
    attached.get_tags.aio.assert_not_awaited()


def test_capability_reads_only_deps_and_keeps_the_harness_configuration():
    governance = SimpleNamespace(network_plan=AsyncMock())
    config = {"app_name": "moyai-test", "working_dir": "/workspace", "sandbox_timeout": 3600, "idle_timeout": 600}
    ctx = SimpleNamespace(deps=SimpleNamespace(session_id=SESSION))
    governed = GovernedModalSandbox(database=SimpleNamespace(governance=governance), **config)
    backend = governed.get_workspace(ctx, ref=None)
    harness = ModalSandbox(**config).get_workspace(ctx, ref=None)
    assert type(backend) is GovernedModalSandboxBackend and isinstance(harness, ModalSandboxBackend)
    attributes = ("_ref", "_image", "_app_name", "_create_app_if_missing", "_sandbox_timeout", "_idle_timeout",
                  "_working_dir", "_env")
    assert [getattr(backend, name) for name in attributes] == [getattr(harness, name) for name in attributes]
    assert backend._governor.session_id == SESSION and backend._governor.database.governance is governance
    governance.network_plan.assert_not_called()
    standalone = GovernedModalSandbox(database=SimpleNamespace(governance=None), **config)
    assert type(standalone.get_workspace(ctx, ref=None)) is GovernedModalSandboxBackend
    assert standalone.get_workspace(ctx, ref=None)._governor is None
    assert governed.get_workspace(ctx, ref=WorkspaceRef(provider="lambda", id="vm")) is None


def test_harness_and_modal_sdk_match_the_reviewed_copy():
    """The governed backend copies harness 0.55.0's _create and relies on _acquire calling _create and _attach.

    Re-review modal_network.GovernedModalSandboxBackend before changing these pins.
    """
    from pydantic_ai_harness.modal_sandbox import _backend
    assert importlib.metadata.version("pydantic-ai-harness") == "0.55.0"
    sources = {
        method.__qualname__: hashlib.sha256(inspect.getsource(method).encode()).hexdigest()
        for method in (ModalSandboxBackend._create, ModalSandboxBackend._acquire, ModalSandboxBackend._attach,
                       ModalSandbox.get_workspace)
    }
    assert sources == {
        "ModalSandboxBackend._create": "640bd9eff379036b44d45c84b01cdd0f201454c9475a22d12bc9552c2d54233d",
        "ModalSandboxBackend._acquire": "29483bb4a3a43fb00397e342b97aa96191620a9cacba943eceb696d97f757d70",
        "ModalSandboxBackend._attach": "cbb7687567ee6005204fcd9f7ed01d04e39c0dc5209a84f0220bfe0a3b880314",
        "ModalSandbox.get_workspace": "fb308a440c3c20cb775eff978f13e089e50fbb141173672342530d91a7b9a84d",
    }
    assert _backend._CREATE_TIMEOUT == 600
    parameters = inspect.signature(modal.Sandbox.create).parameters
    assert {"outbound_domain_allowlist", "outbound_cidr_allowlist", "tags", "block_network"} <= set(parameters)
    assert callable(modal.Sandbox.get_tags.aio) and callable(modal.Sandbox.create.aio)


# Every Modal create, attach and harness backend in native/src/moyai. A new site
# fails here until it is reviewed: 'checked' sites compare the computer's
# creation tag with the session plan before anything runs in it; 'exempt' sites
# only poll, snapshot, keep alive or terminate, or create a network-blocked guest
# that is not a session computer; 'governed' sites build a governed backend.
SITES = {
    ("modal_network", "create_sandbox", "Sandbox.create"): "wrapper",
    ("modal_network", "GovernedModalSandbox.get_workspace", "GovernedModalSandboxBackend"): "governed",
    ("agent", "make_agent", "GovernedModalSandbox"): "governed",
    ("computer", "request", "GovernedModalSandboxBackend"): "governed",
    ("computer_stream", "upstream", "GovernedModalSandboxBackend"): "governed",
    ("product_continuation_restore", "ModalRecoveryTransport.native", "Sandbox.from_id"): "checked",
    ("product_continuation_restore", "ModalRecoveryTransport.native", "Sandbox.from_name"): "checked",
    ("workspace_recovery", "restored_sandbox", "Sandbox.from_name"): "checked",
    ("workspace_recovery", "reused_sandbox", "Sandbox.from_id"): "checked",
    ("product_continuation_restore", "ModalRecoveryTransport.export", "Sandbox.from_id"): "exempt",
    ("product_continuation_restore", "ModalRecoveryTransport.export", "Sandbox.create"): "exempt",
    ("product_continuation_restore", "ModalRecoveryTransport.drain", "Sandbox.from_id"): "exempt",
    ("workspace_recovery", "live_sandbox", "Sandbox.from_id"): "exempt",
    ("computer_keepalive", "keep_computer_alive", "Sandbox.from_id"): "exempt",
    ("answer_settlement", "ModalSnapshots.capture", "Sandbox.from_id"): "exempt",
    ("answer_settlement", "ModalSnapshots.capture", "ModalSandbox"): "exempt",
}
WATCHED = {"ModalSandbox", "ModalSandboxBackend", "GovernedModalSandbox", "GovernedModalSandboxBackend"}
CHECKS = {"reusable", "require_compatible"}


def callee(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = callee(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return None


def watched(call):
    """The watched kind of a call: Sandbox.create/from_id/from_name or a harness sandbox class, else None."""
    parts = (callee(call.func) or "").split(".")
    for index, part in enumerate(parts[:-1]):
        if part == "Sandbox" and parts[index + 1] in {"create", "from_id", "from_name"}:
            return f"Sandbox.{parts[index + 1]}"
    return parts[-1] if parts[-1] in WATCHED else None


def visit(found, module, node, scope, function):
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            inner = child if not isinstance(child, ast.ClassDef) else function
            visit(found, module, child, [*scope, child.name], inner)
            continue
        if isinstance(child, ast.Call) and (kind := watched(child)) is not None:
            found.setdefault((module, ".".join(scope), kind), []).append((child, function))
        visit(found, module, child, scope, function)


def modal_sites():
    """(module, enclosing function, call) -> [(call node, enclosing function node)] for every watched call."""
    found = {}
    for path in sorted(SOURCE.rglob("*.py")):
        module = ".".join(path.relative_to(SOURCE).with_suffix("").parts)
        visit(found, module, ast.parse(path.read_text()), [], None)
    return found


def test_every_modal_create_and_attach_site_is_reviewed():
    found = modal_sites()
    assert set(found) == set(SITES), "Review the new or removed Modal site against modal_network, then list it."
    for site, uses in found.items():
        for call, function in uses:
            keywords = {keyword.arg: keyword.value for keyword in call.keywords}
            if SITES[site] == "checked":
                called = {callee(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}
                assert CHECKS & called, f"{site} must check the computer's network tag before using it."
            if site[2] == "Sandbox.create" and SITES[site] == "exempt":
                # The only other create is a temporary guest with no network at all.
                assert isinstance(keywords.get("block_network"), ast.Constant) and keywords["block_network"].value
            if site[2] == "GovernedModalSandboxBackend":
                assert "governor" in keywords, f"{site} must pass the session's governor."
            if site[2] == "GovernedModalSandbox":
                assert "database" in keywords
            if site[2] == "ModalSandbox":
                # Only the harness backend for a snapshot of an existing ref.
                parent = next(node for node in ast.walk(function) if isinstance(node, ast.Attribute)
                              and node.value is call)
                assert parent.attr == "backend"


# Site behavior with fakes. Each site refuses before anything runs in a wider computer.

def governed_runtime(plan, *, provider="modal"):
    governance = SimpleNamespace(network_plan=AsyncMock(return_value=plan))
    settings = SimpleNamespace(modal_app="moyai-test", computer_lifetime=3600, computer_idle_timeout=600,
                               sandbox_provider=provider)
    return SimpleNamespace(settings=settings, database=SimpleNamespace(governance=governance, settings=settings))


def scope():
    return SimpleNamespace(session_id=SESSION, turn_id="turn", workspace_key="k" * 64)


def blocked(error):
    assert isinstance(error.value, ApplicationError) and error.value.details == ("workspace_network_policy_changed",)


async def test_restored_computers_are_created_under_the_current_plan(monkeypatch):
    from moyai.workspace_recovery import WorkspaceCheckpoint, restored_sandbox
    saved = WorkspaceCheckpoint(session_id=SESSION, workspace={"provider": "modal", "id": "sb-old"}, scope="k" * 64,
                                turn_id="turn", result_fingerprint="r", conversation_digest="c", image_id="im-saved")
    fake = install_modal(monkeypatch, created=computer("sb-restored"))
    monkeypatch.setattr(modal.Image, "from_id", lambda identity: identity)
    runtime = governed_runtime(LISTED)
    assert (await restored_sandbox(runtime, scope(), saved)).object_id == "sb-restored"
    kwargs = fake.create.await_args.kwargs
    assert kwargs["image"] == "im-saved" and kwargs["outbound_domain_allowlist"] == list(LISTED.domains)
    assert kwargs["outbound_cidr_allowlist"] == [] and kwargs["tags"][NETWORK_TAG] == LISTED.tag
    runtime.database.governance.network_plan.assert_awaited_once_with(SESSION)


@pytest.mark.parametrize("lost_reply", [False, True])
async def test_a_reused_wider_restore_computer_is_blocked(monkeypatch, lost_reply):
    from moyai.workspace_recovery import WorkspaceCheckpoint, restored_sandbox
    saved = WorkspaceCheckpoint(session_id=SESSION, workspace={"provider": "modal", "id": "sb-old"}, scope="k" * 64,
                                turn_id="turn", result_fingerprint="r", conversation_digest="c", image_id="im-saved")
    existing = computer("sb-restore")
    fake = install_modal(monkeypatch, existing=existing,
                         create_error=modal.exception.AlreadyExistsError("taken") if lost_reply else None)
    if lost_reply:
        fake.from_name.side_effect = [modal.exception.NotFoundError("no"), existing]
    monkeypatch.setattr(modal.Image, "from_id", lambda identity: identity)
    with pytest.raises(ApplicationError) as error:
        await restored_sandbox(governed_runtime(NOTHING), scope(), saved)
    blocked(error)
    existing.exec.aio.assert_not_awaited()


async def test_continuation_computers_are_created_under_the_plan_and_reuse_is_checked(monkeypatch):
    from moyai.product_continuation_restore import ModalRecoveryTransport
    fake = install_modal(monkeypatch, created=computer("sb-product"))
    monkeypatch.setattr("moyai.product_continuation_restore.runtime_image", lambda base: "image")
    transport = ModalRecoveryTransport(governed_runtime(LISTED))
    assert (await transport.native(scope(), {}, None)).object_id == "sb-product"
    assert fake.create.await_args.kwargs["tags"] == {NETWORK_TAG: LISTED.tag, SESSION_TAG: SESSION}
    # A reused computer, by name or by its stored reference, is checked before
    # restoration or repository preparation can exec in it.
    wider = computer("sb-wider")
    fake.from_name.side_effect, fake.from_name.return_value = None, wider
    with pytest.raises(ApplicationError) as error:
        await transport.native(scope(), {}, None)
    blocked(error)
    fake.from_id.return_value = wider
    with pytest.raises(ApplicationError) as error:
        await transport.native(scope(), {}, {"provider": "modal", "id": "sb-wider"})
    blocked(error)
    wider.exec.aio.assert_not_awaited()
    fake.from_id.return_value = same = tagged(LISTED, "sb-same")
    assert await transport.native(scope(), {}, {"provider": "modal", "id": "sb-same"}) is same


@pytest.mark.parametrize("reference", [None, {"provider": "lambda", "id": "lambda:us-east-1:vm"}])
async def test_restricted_continuations_never_reach_lambda(monkeypatch, reference):
    from moyai.product_continuation_restore import ModalRecoveryTransport
    control = SimpleNamespace(create=AsyncMock(), get=AsyncMock())
    monkeypatch.setattr("moyai.lambda_control.LambdaControl", lambda settings: control)
    transport = ModalRecoveryTransport(governed_runtime(NOTHING, provider="lambda"))
    with pytest.raises(NetworkPolicyRefused, match="Lambda computers cannot enforce"):
        await transport.native(scope(), {}, reference)
    control.create.assert_not_awaited()
    control.get.assert_not_awaited()


async def test_human_desktop_actions_refuse_a_wider_computer_before_the_guest_runs(monkeypatch):
    from moyai.computer import request
    attached = computer()
    install_modal(monkeypatch, attached=attached)
    session = SimpleNamespace(id=SESSION, workspace=json.dumps({"provider": "modal", "id": "sb-computer"}))
    with pytest.raises(HTTPException) as error:
        await request(governed_runtime(LISTED), session, {"action": "start", "deadline": 0})
    assert error.value.status_code == 409 and "different network policy" in error.value.detail
    attached.exec.aio.assert_not_awaited()


async def test_human_desktop_actions_refuse_restricted_lambda_computers(monkeypatch):
    from moyai.computer import request
    from moyai.lambda_control import LambdaControl
    get = AsyncMock()
    monkeypatch.setattr(LambdaControl, "get", get)
    session = SimpleNamespace(id=SESSION, workspace=json.dumps({"provider": "lambda", "id": "lambda:us-east-1:vm"}))
    with pytest.raises(HTTPException) as error:
        await request(governed_runtime(NOTHING), session, {"action": "frame", "deadline": 0})
    assert error.value.status_code == 409 and "Lambda computers cannot enforce" in error.value.detail
    get.assert_not_awaited()


@pytest.mark.parametrize("controlling", [False, True])
async def test_desktop_streams_refuse_a_wider_computer_before_a_connect_token(monkeypatch, controlling):
    from moyai.computer_stream import StreamAccess, upstream
    attached = computer()
    install_modal(monkeypatch, attached=attached)
    access = StreamAccess(session_id=SESSION, actor=SimpleNamespace(id="actor"), client_id="client",
                          workspace=json.dumps({"provider": "modal", "id": "sb-computer"}),
                          epoch="epoch" if controlling else None)
    with pytest.raises(NetworkPolicyMismatch):
        async with upstream(governed_runtime(LISTED), access):
            pytest.fail("A wider computer reached the desktop stream.")
    attached.create_connect_token.aio.assert_not_awaited()


def test_governor_is_absent_when_nothing_is_governed():
    assert NetworkGovernor.of(SimpleNamespace(governance=None), SESSION) is None
    assert NetworkGovernor.of(SimpleNamespace(), SESSION) is None
    assert NetworkGovernor.of(SimpleNamespace(governance=object()), SESSION).session_id == SESSION
