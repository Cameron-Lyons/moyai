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

Standalone native installs do not ship the canonical app package, so it is
imported only on paths that a spend refusal (existing-product mode) reaches.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING, TypeGuard

from temporalio.exceptions import ApplicationError

if TYPE_CHECKING:
    from app.spend_limits import SpendLimitReached

DENIED = "x-moyai-inference-denied"
REASON = "x-moyai-inference-denied-reason"
ERROR_TYPE = "MoyaiSpendLimitReached"
# Turn workflows that see a spend refusal publish its sentence.
VERSION = "moyai-spend-limit-failures-v1"


def is_refusal(error: BaseException | None) -> TypeGuard[SpendLimitReached]:
    """Whether error is a spend refusal; only a loaded app.spend_limits can have raised one."""
    reached = getattr(sys.modules.get("app.spend_limits"), "SpendLimitReached", None)
    return reached is not None and isinstance(error, reached)


def denied_headers(error: BaseException | None) -> dict[str, str]:
    """The broker's fixed refusal headers for an admission error; only a spend reason is named."""
    headers = {DENIED: "1"}
    if is_refusal(error):
        headers[REASON] = "spend-" + error.reason
    return headers


def broker_refusal(headers: Mapping[str, str]) -> SpendLimitReached | None:
    """The spend refusal a broker reported, or None for any other or unknown reason."""
    value = headers.get(REASON) or ""
    if not value.startswith("spend-"):
        return None
    from app.spend_limits import REACHED, SpendLimitReached
    reason = value.removeprefix("spend-")
    return SpendLimitReached(reason) if reason in REACHED else None


def denial(error: SpendLimitReached) -> ApplicationError:
    """The typed, non-retryable activity failure; Temporal must not retry a refused request."""
    from app.spend_limits import REACHED
    return ApplicationError(REACHED[error.reason], type=ERROR_TYPE, non_retryable=True)


def notice(message: str) -> str | None:
    """message when it is one of the fixed spend refusal sentences, else None."""
    from app.spend_limits import REACHED
    return message if message in REACHED.values() else None
