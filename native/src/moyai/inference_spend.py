"""Spend limit refusals carried from model admission to the turn's failure notice.

ProductGovernance.check_model refuses a paid model request with
app.spend_limits.SpendLimitReached, whose reason selects one fixed sentence
without amounts. In split deployments the broker forwards only that reason, in a
server-owned header next to x-moyai-inference-denied, and the worker rebuilds
the same refusal; a missing or unknown value keeps the generic admission
refusal, so the request is refused either way and only the message differs.
The activity interceptor raises a non-retryable MoyaiSpendLimitReached with the
sentence, as the last failure of its chain, and TurnWorkflow publishes that
sentence (failure_diagnostics.spend_notice) as the turn's error, so the web
failure banner and the Slack thread say why.
"""

from __future__ import annotations

from collections.abc import Mapping

from app.spend_limits import REACHED, SpendLimitReached
from temporalio.exceptions import ApplicationError

DENIED = "x-moyai-inference-denied"
REASON = "x-moyai-inference-denied-reason"
ERROR_TYPE = "MoyaiSpendLimitReached"
# Turn workflows that see a spend refusal publish its sentence.
VERSION = "moyai-spend-limit-failures-v1"


def denied_headers(error: BaseException | None) -> dict[str, str]:
    """The broker's fixed refusal headers for an admission error; only a spend reason is named."""
    headers = {DENIED: "1"}
    if isinstance(error, SpendLimitReached):
        headers[REASON] = "spend-" + error.reason
    return headers


def broker_refusal(headers: Mapping[str, str]) -> SpendLimitReached | None:
    """The spend refusal a broker reported, or None for any other or unknown reason."""
    value = headers.get(REASON) or ""
    reason = value.removeprefix("spend-")
    return SpendLimitReached(reason) if value.startswith("spend-") and reason in REACHED else None


def denial(error: SpendLimitReached) -> ApplicationError:
    """The typed, non-retryable activity failure; Temporal must not retry a refused request."""
    return ApplicationError(REACHED[error.reason], type=ERROR_TYPE, non_retryable=True)
