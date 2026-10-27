"""Gateway guardrail refusals become one typed, content-free denial."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx2 as httpx
import pytest
from app.config import GUARDRAIL_NAMES as PRODUCT_GUARDRAIL_NAMES
from app.config import Settings as ProductSettings
from openai import AsyncOpenAI
from pydantic import ValidationError
from pydantic_ai import ConversationTypeAdapter
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.openai import OpenAIResponsesModel
from pydantic_ai.providers.litellm import LiteLLMProvider
from temporalio import workflow
from temporalio.client import WorkflowFailureError
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import ExecuteActivityInput, Replayer
from test_inference_usage import WireStream, bound, payload, request, rows, transport

from moyai.contracts import NewMessage, NewSession
from moyai.execution import AuthorizedActivity
from moyai.failure_diagnostics import capture_failure, guardrail_outcome
from moyai.failure_report import FailureReport
from moyai.inference_guardrails import (
    APPLIED,
    MESSAGES,
    VERSION,
    GuardrailUnattested,
    blocked,
    names,
    unattested,
)
from moyai.inference_usage import InferenceUsageTransport
from moyai.models import Session, Turn
from moyai.settings import GUARDRAIL_NAMES, Settings
from moyai.storage import encrypted_converter
from moyai.worker import make_worker
from moyai.worker_capacity import ActivityCapacity
from moyai.workflow import TurnWorkflow

FLAGGED = "flagged-private-input"


def litellm_error(message, *, fields=None, code="400"):
    # ProxyException.to_dict() under openai_exception_handler's {"error": ...}.
    error = {"message": message, "type": "invalid_request_error", "param": None, "code": code}
    if fields is not None:
        error["provider_specific_fields"] = fields
    return json.dumps({"error": error}).encode()


# Shapes LiteLLM 1.106.4 produces for a blocking guardrail.
REFUSALS = {
    # HTTPException(detail=dict), enriched by enrich_http_exception_with_guardrail_context.
    "http_exception": (litellm_error("Violated guardrail policy", fields={
        "error": "Violated guardrail policy", "bedrock_guardrail_response": FLAGGED,
        "guardrail_name": "bedrock-input", "guardrail_mode": "pre_call",
    }), "bedrock-input", "pre_call"),
    "content_filter": (litellm_error(f"Content blocked: {FLAGGED}", fields={
        "error": f"Content blocked: {FLAGGED}", "matched_phrase": FLAGGED,
        "guardrail_name": "phi-filter", "guardrail_mode": "during_call",
    }), "phi-filter", "during_call"),
    # GuardrailRaisedException's default wrapping.
    "raised": (litellm_error(
        f"Guardrail raised an exception, Guardrail: presidio-pii, Message: {FLAGGED}",
    ), "presidio-pii", None),
    # BlockedPiiEntityError.
    "pii_entity": (litellm_error(
        "Blocked entity detected: US_SSN by Guardrail: presidio-pii.v2. "
        "This entity is not allowed to be used in this request.",
    ), "presidio-pii.v2", None),
}


@pytest.mark.parametrize("status", [400, 403, 422])
@pytest.mark.parametrize("shape", sorted(REFUSALS))
def test_litellm_refusal_shapes_keep_only_attested_names(shape, status):
    body, name, mode = REFUSALS[shape]
    guardrail = blocked(status, "prompt-injection, presidio-pii,presidio-pii.v2, bad name!, " + "x" * 101, body)
    assert guardrail is not None and guardrail.outcome == "blocked"
    assert (guardrail.name, guardrail.mode) == (name, mode)
    assert guardrail.applied == ("prompt-injection", "presidio-pii", "presidio-pii.v2")
    details = guardrail.details("session-one", "route-alias")
    assert details["guardrails"] == ["prompt-injection", "presidio-pii", "presidio-pii.v2"]
    assert FLAGGED not in json.dumps(details) and "Violated" not in json.dumps(details)


def test_unattested_or_invalid_names_are_not_recorded():
    reported = litellm_error("Violated guardrail policy", fields={"guardrail_name": "bad name!"})
    guardrail = blocked(400, "prompt-injection", reported)
    assert guardrail is not None and guardrail.name is None
    # A wrapper alone could be quoted input; only an attested name makes it a refusal.
    unlisted = litellm_error(f"Guardrail raised an exception, Guardrail: unlisted, Message: {FLAGGED}")
    assert blocked(400, "prompt-injection", unlisted) is None
    # The name is read right after the wrapper, never from the quoted message.
    quoted = litellm_error("Guardrail raised an exception, Guardrail: unlisted, Message: by Guardrail: prompt-injection")
    assert blocked(400, "prompt-injection", quoted) is None


# Guardrail failures LiteLLM 1.106.4 reports with other statuses, and errors
# that only mention a guardrail; none is a decision about the content.
@pytest.mark.parametrize("status, body", [
    (429, litellm_error("Rate limit exceeded", code="429")),
    (400, litellm_error("This model's maximum context length is 128000 tokens.")),
    (400, litellm_error("Invalid schema for function 'mcp_guardrail_lookup': missing 'type'.")),
    (502, b"<html>Bad gateway</html>"),
    (400, json.dumps({"detail": "Violated guardrail policy"}).encode()),
    (400, json.dumps([{"error": {"message": "guardrail"}}]).encode()),
    # cisco_ai_defense.py, enriched with the raising guardrail's name.
    (503, litellm_error("Cisco AI Defense guardrail unavailable", code="503", fields={
        "error": "Cisco AI Defense guardrail unavailable", "guardrail_name": "prompt-injection",
        "guardrail_mode": "pre_call",
    })),
    (500, litellm_error("Bedrock InvokeGuardrailChecks returned an unexpected response shape", code="500", fields={
        "error": "Bedrock InvokeGuardrailChecks returned an unexpected response shape",
        "guardrail_name": "prompt-injection", "guardrail_mode": "pre_call",
    })),
    (500, litellm_error("Bedrock guardrail throttle retries exhausted", code="500")),
    (408, litellm_error("File sanitization timeout", code="408", fields={
        "guardrail_name": "prompt-injection",
    })),
    # generic_guardrail_api.py with its default fail_closed unreachable_fallback.
    (500, litellm_error("Generic Guardrail API failed: ConnectError('All connection attempts failed')", code="500")),
    (500, litellm_error(
        "Guardrail raised an exception, Guardrail: prompt-injection, Message: backend unreachable", code="500",
    )),
    # The generic guardrail API's unwrapped block names no guardrail.
    (400, litellm_error("Content violates policy")),
])
def test_guardrail_failures_and_ordinary_errors_are_not_refusals(status, body):
    # x-litellm-applied-guardrails lists every guardrail that ran, including
    # ones that passed before a provider error; it never classifies alone.
    assert blocked(status, "prompt-injection", body) is None


def test_a_wrapped_fail_closed_outage_still_reads_as_a_refusal():
    # LiteLLM serializes no GuardrailRaisedException.blocked_content, so a
    # backend outage that keeps the default wrapper and 400 is indistinguishable.
    outage = litellm_error(
        "Guardrail raised an exception, Guardrail: llm-shield, "
        "Message: LLM Shield Proxy is unreachable; blocking the request.",
    )
    assert blocked(400, "llm-shield", outage).name == "llm-shield"


def test_applied_header_names_are_bounded():
    assert names(None) == names("") == ()
    assert names(",".join(f"g{index}" for index in range(70))) == tuple(f"g{index}" for index in range(64))
    assert names("a,a, b ,\x00c") == ("a", "b")
    many = blocked(400, ",".join(f"g{index}" for index in range(64)), REFUSALS["http_exception"][0])
    assert len(many.details("session-one", "route-alias")["guardrails"]) == 10


def test_unattested_answers_name_only_missing_required_guardrails():
    assert unattested("phi-presidio, prompt-injection", ("phi-presidio",)) is None
    guardrail = unattested("prompt-injection,bad name!", ("phi-presidio", "prompt-injection"))
    assert guardrail is not None and guardrail.outcome == "unattested" and guardrail.name is None
    assert guardrail.details("session-one", "route-alias") == {
        "session_id": "session-one", "model": "route-alias",
        "guardrails": ["prompt-injection"], "missing": ["phi-presidio"],
    }
    assert unattested(None, ("phi-presidio",)).missing == ("phi-presidio",)


@pytest.mark.parametrize("value, expected", [
    ("", ()), ("phi-presidio", ("phi-presidio",)),
    ("phi-presidio , prompt-injection,phi-presidio", ("phi-presidio", "prompt-injection")),
    ("prompt-injection,phi-presidio", ("phi-presidio", "prompt-injection")),
    ("phi presidio", None), ("phi-presidio,", None), ("x" * 65, None), (",".join("g" * 11), None),
])
def test_required_guardrails_are_validated_canonical_names(value, expected):
    # The product setting cannot import the native module; one grammar keeps both.
    assert PRODUCT_GUARDRAIL_NAMES == GUARDRAIL_NAMES
    if expected is None:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, required_guardrails=value)
        with pytest.raises(ValidationError):
            ProductSettings(_env_file=None, moyai_required_guardrails=value)
    else:
        assert Settings(_env_file=None, required_guardrails=value).guardrails == expected
        # Roles listing the same names in another order share one contract.
        assert ProductSettings(_env_file=None, moyai_required_guardrails=value).moyai_required_guardrails == (
            Settings(_env_file=None, required_guardrails=value).required_guardrails
        ) == ",".join(expected)


def test_guardrail_outcome_reads_the_captured_failure_chain():
    try:
        try:
            raise ApplicationError("x", type="MoyaiGuardrailUnattested", non_retryable=True)
        except ApplicationError as cause:
            raise RuntimeError("agent run failed") from cause
    except RuntimeError as error:
        assert guardrail_outcome(capture_failure(error)) == "unattested"
    assert guardrail_outcome(capture_failure(ApplicationError("x", type="MoyaiInferenceAdmissionDenied"))) is None
    assert guardrail_outcome(None) is None


async def test_refused_response_is_unchanged_and_marks_the_activity(runtime):
    body, _, _ = REFUSALS["http_exception"]
    response, context, _ = await request(
        runtime, body, status=400,
        headers={"content-type": "application/json", APPLIED: "bedrock-input"},
    )
    assert response.status_code == 400 and response.content == body
    assert context.guardrail == "blocked" and context.latest.guardrail.name == "bedrock-input"
    usage, = await rows(runtime)
    # LiteLLM records a refused request at zero spend, like any gateway error.
    assert usage.status == "failed" and usage.coverage_error == "gateway_error" and usage.cost_usd is None
    assert FLAGGED not in repr({column.name: getattr(usage, column.name) for column in usage.__table__.columns})


@pytest.mark.parametrize("status, body, encoding", [
    (429, litellm_error("Rate limit exceeded", code="429"), "identity"),
    (503, REFUSALS["http_exception"][0], "identity"),
    (400, REFUSALS["http_exception"][0], "br"),
])
async def test_unclassified_errors_leave_the_activity_unmarked(runtime, status, body, encoding):
    response, context, _ = await request(runtime, body, status=status, headers={
        "content-type": "application/json", "content-encoding": encoding, APPLIED: "bedrock-input",
    })
    assert response.status_code == status and context.guardrail is None


@pytest.mark.parametrize("applied, refused", [
    ("prompt-injection", True), ("prompt-injection, phi-presidio", False), (None, True),
])
async def test_required_guardrails_must_attest_before_the_sdk_reads_an_answer(runtime, monkeypatch, applied, refused):
    monkeypatch.setattr(runtime.database.settings, "required_guardrails", "phi-presidio")
    headers = {"content-type": "application/json", **({APPLIED: applied} if applied else {})}
    adapter, stream = transport(json.dumps(payload(cost="0.2")).encode(), headers=headers)
    with bound(runtime) as context:
        async with httpx.AsyncClient(transport=adapter) as client:
            if refused:
                with pytest.raises(GuardrailUnattested):
                    await client.post("https://gateway.invalid/v1/responses", json={"model": "route-alias"})
            else:
                assert (await client.post(
                    "https://gateway.invalid/v1/responses", json={"model": "route-alias"},
                )).status_code == 200
    assert context.guardrail == ("unattested" if refused else None)
    usage, = await rows(runtime)
    # The answer was paid for but never read; its cost is left to recovery.
    assert (usage.status, usage.cost_usd) == (("interrupted", None) if refused else ("completed", "0.2"))
    assert stream.closed


async def test_attestation_is_off_without_required_guardrails(runtime):
    response, context, _ = await request(runtime, json.dumps(payload()).encode())
    assert response.status_code == 200 and context.guardrail is None


@pytest.mark.parametrize("outcome", ["blocked", "unattested"])
async def test_refusal_is_a_non_retryable_denial_without_gateway_text(runtime, active, monkeypatch, outcome):
    _, _, prepared = active
    info = SimpleNamespace(
        activity_type="agent__moyai__model_request", workflow_namespace="default",
        workflow_id="workflow", workflow_run_id="run", activity_id="activity", attempt=1,
    )
    monkeypatch.setattr("moyai.execution.activity.info", lambda: info)
    monkeypatch.setattr(runtime.database.settings, "required_guardrails", "phi-presidio")
    body, _, _ = REFUSALS["http_exception"]

    async def gateway(_request):
        if outcome == "unattested":
            return httpx.Response(200, stream=WireStream(json.dumps(payload()).encode()), headers={
                "content-type": "application/json", APPLIED: "prompt-injection",
            })
        return httpx.Response(400, stream=WireStream(body), headers={"content-type": "application/json"})

    class Next:
        async def execute_activity(self, _input):
            async with httpx.AsyncClient(transport=InferenceUsageTransport(httpx.MockTransport(gateway))) as client:
                sdk = AsyncOpenAI(base_url="https://gateway.invalid/v1", api_key="synthetic", max_retries=0,
                                  http_client=client)
                model = OpenAIResponsesModel(prepared.scope.model, provider=LiteLLMProvider(openai_client=sdk))
                await model.request(
                    [ModelRequest(parts=[UserPromptPart(FLAGGED)])], None, ModelRequestParameters(),
                )

    interceptor = AuthorizedActivity(Next(), runtime.database)
    value = ExecuteActivityInput(fn=lambda: None, args=[prepared.scope], executor=None, headers={})
    with pytest.raises(ApplicationError) as denied:
        await interceptor.execute_activity(value)
    assert denied.value.non_retryable and denied.value.type == {
        "blocked": "MoyaiGuardrailBlocked", "unattested": "MoyaiGuardrailUnattested",
    }[outcome]
    assert denied.value.message == MESSAGES[outcome]
    assert denied.value.__cause__ is None and denied.value.__suppress_context__


@pytest.mark.parametrize("runtime", ["guardrail"], indirect=True)
@pytest.mark.parametrize("old_history", [False, True])
async def test_refused_turn_publishes_notice_without_preserving_context(runtime, active, monkeypatch, old_history):
    _, turn, _ = active
    original_patched = workflow.patched
    if old_history:
        def before_guardrails(identity, **kwargs):
            return False if identity == VERSION else original_patched(identity, **kwargs)
        monkeypatch.setattr(workflow, "patched", before_guardrails)
    converter = encrypted_converter(runtime.security, runtime.objects)
    async with await WorkflowEnvironment.start_local(
        plugins=[PydanticAIPlugin()], data_converter=converter,
    ) as environment:
        runtime.client = environment.client
        async with make_worker(runtime):
            handle = await runtime.client.start_workflow(
                TurnWorkflow.run, turn.id, id=turn.workflow_id, task_queue=runtime.settings.temporal_queue,
            )
            with pytest.raises(WorkflowFailureError) as failed:
                await asyncio.wait_for(handle.result(), 30)
            history = await handle.fetch_history()
    assert isinstance(failed.value.cause, ApplicationError)
    async with runtime.database.sessions() as db:
        row = await db.get(Turn, turn.id)
        assert row.status == "failed" and FLAGGED not in row.error
        assert row.error == (MESSAGES["blocked"] if not old_history else (
            "The agent could not complete this turn. "
            "Inspect the saved activity before repeating a possibly completed action."
        ))
    scheduled = [
        event.activity_task_scheduled_event_attributes.activity_type.name for event in history.events
        if event.HasField("activity_task_scheduled_event_attributes")
    ]
    assert ("moyai_preserve_failed_workspace_v1" in scheduled) == old_history
    failures = [
        event.activity_task_failed_event_attributes.failure for event in history.events
        if event.HasField("activity_task_failed_event_attributes")
    ]
    refused, = (failure for failure in failures if failure.application_failure_info.type == "MoyaiGuardrailBlocked")
    assert refused.application_failure_info.non_retryable and not refused.HasField("cause")
    assert FLAGGED not in str(refused)
    started = [
        event.activity_task_started_event_attributes.attempt for event in history.events
        if event.HasField("activity_task_started_event_attributes")
    ]
    assert max(started) == 1
    # Slack's failure report keeps the notice and leaves the refused trace out.
    report = await FailureReport.for_turn(runtime, row)
    assert report.debug_log is None and report.text.endswith(row.error)
    monkeypatch.setattr(workflow, "patched", original_patched)
    await Replayer(
        interceptors=[ActivityCapacity()],
        workflows=[TurnWorkflow], plugins=[PydanticAIPlugin()], data_converter=converter,
    ).replay_workflow(history)


async def test_rebuilt_context_leaves_out_a_refused_turns_messages(runtime, actor):
    session = await runtime.database.create_session(actor, NewSession())
    for key, prompt in (("kept", "Kept context"), ("refused", FLAGGED)):
        turn = await runtime.database.submit(actor, session.id, NewMessage(prompt=prompt, request_key=key))
        async with runtime.database.sessions.begin() as db:
            saved = await db.get(Turn, turn.id)
            saved.status, saved.error = ("completed", None) if key == "kept" else ("failed", MESSAGES["blocked"])
            (await db.get(Session, session.id)).active_turn = None
    async with runtime.database.sessions.begin() as db:
        # Another requester's saved context: the next turn rebuilds it from public messages.
        saved = await db.get(Session, session.id)
        saved.conversation = runtime.security.seal("Different actor/model context")
        saved.last_actor_id = None
    current = await runtime.database.submit(actor, session.id, NewMessage(prompt="Next", request_key="next"))
    assert (await runtime.database.claim_next()).id == current.id
    prepared = await runtime.database.prepare(current.id)
    history, = ConversationTypeAdapter.validate_json(prepared.conversation).messages
    assert "Kept context" in history.parts[0].content and FLAGGED not in prepared.conversation
