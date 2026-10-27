"""Spend limit refusals keep their fixed reason from admission to the turn's failure notice."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx2 as httpx
import pytest
from app.spend_limits import REACHED, SpendLimitReached
from pydantic_ai.durable_exec.temporal import PydanticAIPlugin
from temporalio import workflow
from temporalio.client import WorkflowFailureError
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import ExecuteActivityInput, Replayer

from moyai.execution import AuthorizedActivity
from moyai.failure_diagnostics import capture_failure, failure_summary, spend_notice
from moyai.failure_report import FailureReport
from moyai.inference_spend import ERROR_TYPE, REASON, VERSION, broker_refusal, denied_headers
from moyai.models import Turn
from moyai.product_inference import InferenceAdmissionError
from moyai.storage import encrypted_converter
from moyai.worker import make_worker
from moyai.worker_capacity import ActivityCapacity
from moyai.workflow import TurnWorkflow

GENERIC = "The agent could not complete this turn. Inspect the saved activity before repeating a possibly completed action."


@pytest.mark.parametrize("reason", sorted(REACHED))
def test_only_a_spend_refusal_names_its_reason_to_the_worker(reason):
    headers = denied_headers(SpendLimitReached(reason))
    assert headers == {"x-moyai-inference-denied": "1", REASON: "spend-" + reason}
    refused = broker_refusal(httpx.Headers(headers))
    assert isinstance(refused, SpendLimitReached) and refused.reason == reason
    assert denied_headers(InferenceAdmissionError("Inference authority changed.")) == {"x-moyai-inference-denied": "1"}
    assert denied_headers(None) == {"x-moyai-inference-denied": "1"}


@pytest.mark.parametrize("value", [None, "", "spend-", "spend-group", "spend-USER", "user", "guardrail-blocked",
                                   "spend-user, spend-session"])
def test_unknown_broker_reasons_keep_the_generic_refusal(value):
    assert broker_refusal(httpx.Headers({} if value is None else {REASON: value})) is None


def test_notice_reads_only_a_fixed_sentence_from_the_failure_chain():
    try:
        try:
            raise ApplicationError(REACHED["session"], type=ERROR_TYPE, non_retryable=True)
        except ApplicationError as cause:
            raise RuntimeError("agent run failed") from cause
    except RuntimeError as error:
        assert spend_notice(error) == REACHED["session"]
    assert spend_notice(ApplicationError("You spent $12.34.", type=ERROR_TYPE)) is None
    assert spend_notice(ApplicationError(REACHED["user"], type="MoyaiInferenceAdmissionDenied")) is None
    assert spend_notice(None) is None


@pytest.mark.parametrize("reason", ["session", "pending"])
async def test_interceptor_raises_a_non_retryable_spend_denial(runtime, active, monkeypatch, reason):
    _, _, prepared = active
    info = SimpleNamespace(
        activity_type="agent__moyai__model_request", workflow_namespace="default",
        workflow_id="workflow", workflow_run_id="run", activity_id="activity", attempt=1,
    )
    monkeypatch.setattr("moyai.execution.activity.info", lambda: info)

    class Next:
        async def execute_activity(self, _input):
            from moyai.inference_usage import INFERENCE_ACTIVITY
            activity = INFERENCE_ACTIVITY.get()
            assert activity is not None
            activity.admission_error = SpendLimitReached(reason)
            raise RuntimeError("Connection error.")

    interceptor = AuthorizedActivity(Next(), runtime.database)
    value = ExecuteActivityInput(fn=lambda: None, args=[prepared.scope], executor=None, headers={})
    with pytest.raises(ApplicationError) as denied:
        await interceptor.execute_activity(value)
    assert denied.value.type == ERROR_TYPE and denied.value.non_retryable
    assert denied.value.message == REACHED[reason]
    # The typed denial ends its chain, so a parent's subagent summary names it, not the transport error.
    assert capture_failure(denied.value) == {"exception_chain": [
        {"type": "ApplicationError", "application_type": ERROR_TYPE}]}


@pytest.mark.parametrize("runtime", ["spend"], indirect=True)
@pytest.mark.parametrize("old_history", [False, True])
async def test_refused_turn_says_why_in_the_web_and_slack_failure(runtime, active, monkeypatch, old_history):
    _, turn, _ = active
    original_patched = workflow.patched
    if old_history:
        def before_spend_notices(identity, **kwargs):
            return False if identity == VERSION else original_patched(identity, **kwargs)
        monkeypatch.setattr(workflow, "patched", before_spend_notices)
    converter = encrypted_converter(runtime.security, runtime.objects)
    async with await WorkflowEnvironment.start_local(
        plugins=[PydanticAIPlugin()], data_converter=converter,
    ) as environment:
        runtime.client = environment.client
        async with make_worker(runtime):
            handle = await runtime.client.start_workflow(
                TurnWorkflow.run, turn.id, id=turn.workflow_id, task_queue=runtime.settings.temporal_queue,
            )
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 30)
            history = await handle.fetch_history()
    async with runtime.database.sessions() as db:
        row = await db.get(Turn, turn.id)
        summary = await failure_summary(runtime.database, db, row)
    assert row.status == "failed"
    assert row.error == (GENERIC if old_history else REACHED["user"])
    # A delegating parent reads this summary of its child's failure.
    assert summary.startswith(f"Subagent failed: {ERROR_TYPE} during "), summary
    failures = [
        event.activity_task_failed_event_attributes.failure for event in history.events
        if event.HasField("activity_task_failed_event_attributes")
    ]
    refused, = (failure for failure in failures if failure.application_failure_info.type == ERROR_TYPE)
    assert refused.application_failure_info.non_retryable
    started = [
        event.activity_task_started_event_attributes.attempt for event in history.events
        if event.HasField("activity_task_started_event_attributes")
    ]
    assert max(started) == 1
    # The Slack thread's failure report carries the same sentence, and keeps its debug log.
    report = await FailureReport.for_turn(runtime, row)
    assert report.text == f"This task stopped before it completed: {row.error}"
    assert report.debug_log is not None
    monkeypatch.setattr(workflow, "patched", original_patched)
    await Replayer(
        interceptors=[ActivityCapacity()],
        workflows=[TurnWorkflow], plugins=[PydanticAIPlugin()], data_converter=converter,
    ).replay_workflow(history)
