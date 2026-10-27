"""Spend limit refusals keep their fixed reason from admission to the turn's failure notice."""

from __future__ import annotations

import httpx2 as httpx
import pytest
from app.spend_limits import REACHED, SpendLimitReached
from temporalio.exceptions import ApplicationError
from test_inference_guardrails import denied_attempt, failed_turn

from moyai.failure_diagnostics import capture_failure, failure_summary, spend_notice
from moyai.failure_report import FailureReport
from moyai.inference_spend import ERROR_TYPE, REASON, VERSION, broker_refusal, denied_headers
from moyai.inference_usage import INFERENCE_ACTIVITY
from moyai.models import Turn
from moyai.product_inference import InferenceAdmissionError

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
    error = RuntimeError("agent run failed")
    error.__cause__ = ApplicationError(REACHED["session"], type=ERROR_TYPE, non_retryable=True)
    assert spend_notice(error) == REACHED["session"]
    assert spend_notice(ApplicationError("You spent $12.34.", type=ERROR_TYPE)) is None
    assert spend_notice(ApplicationError(REACHED["user"], type="MoyaiInferenceAdmissionDenied")) is None
    assert spend_notice(None) is None


@pytest.mark.parametrize("reason", ["session", "pending"])
async def test_interceptor_raises_a_non_retryable_spend_denial(runtime, active, monkeypatch, reason):
    _, _, prepared = active

    async def execute(_input):
        activity = INFERENCE_ACTIVITY.get()
        assert activity is not None
        activity.admission_error = SpendLimitReached(reason)
        raise RuntimeError("Connection error.")

    denied = await denied_attempt(runtime, monkeypatch, prepared.scope, execute)
    assert denied.type == ERROR_TYPE and denied.non_retryable
    assert denied.message == REACHED[reason]
    # The typed denial ends its chain, so a parent's subagent summary names it, not the transport error.
    assert capture_failure(denied) == {"exception_chain": [
        {"type": "ApplicationError", "application_type": ERROR_TYPE}]}


@pytest.mark.parametrize("runtime", ["spend"], indirect=True)
@pytest.mark.parametrize("old_history", [False, True])
async def test_refused_turn_says_why_in_the_web_and_slack_failure(runtime, active, monkeypatch, old_history):
    _, turn, _ = active
    await failed_turn(runtime, turn, monkeypatch, version=VERSION, old_history=old_history, error_type=ERROR_TYPE)
    async with runtime.database.sessions() as db:
        row = await db.get(Turn, turn.id)
        summary = await failure_summary(runtime.database, db, row)
    assert row.status == "failed"
    assert row.error == (GENERIC if old_history else REACHED["user"])
    # A delegating parent reads this summary of its child's failure.
    assert summary.startswith(f"Subagent failed: {ERROR_TYPE} during "), summary
    # The Slack thread's failure report carries the same sentence, and keeps its debug log.
    report = await FailureReport.for_turn(runtime, row)
    assert report.text == f"This task stopped before it completed: {row.error}"
    assert report.debug_log is not None
