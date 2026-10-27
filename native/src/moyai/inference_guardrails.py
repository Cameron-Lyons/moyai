"""Gateway AI guardrail refusals, read from LiteLLM's proxy error shapes; no classifier.

LiteLLM's proxy (verified against 1.106.4) refuses a request that a pre_call or
during_call guardrail blocks before any model output, as an OpenAI error object.
Only 400, 403 and 422 signal a block (custom_guardrail.py
_GUARDRAIL_BLOCK_STATUS_CODES); other statuses are guardrail or provider
failures, such as an unavailable guardrail backend's 5xx, never refusals here.
Guardrails raising HTTPException with a dict detail carry that detail, enriched
with guardrail_name and guardrail_mode, as error.provider_specific_fields.
GuardrailRaisedException and BlockedPiiEntityError name the guardrail only in
error.message ("Guardrail raised an exception, Guardrail: <name>, ..." and
"... by Guardrail: <name>. ..."), so such a message counts only when it names a
guardrail in x-litellm-applied-guardrails. That header lists every guardrail
that ran, so it also appears on ordinary provider errors and never classifies
by itself. LiteLLM does not serialize GuardrailRaisedException.blocked_content,
so a guardrail that fails closed this way because its backend was unreachable
is indistinguishable from a block.

A successful answer lists the guardrails that ran in the same header, before
any streamed content, so MOYAI_REQUIRED_GUARDRAILS can fail closed when one is
missing: the broker or transport refuses the answer before the SDK reads it.

Only names that pass NAME, the mode and the outcome leave this module. Error
messages and provider fields can quote the blocked content and are never kept.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from temporalio.exceptions import ApplicationError

BLOCKED, UNATTESTED = "blocked", "unattested"
# Server-owned broker-to-worker outcome; never forwarded from the gateway.
HEADER = "x-moyai-guardrail"
APPLIED = "x-litellm-applied-guardrails"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
MAX_NAMES = 64
# Keeps every event's details far below the audit's 4096-byte bound.
MAX_AUDIT_NAMES = 10
MAX_ERROR_BYTES = 64 * 1024
BLOCK_STATUSES = frozenset({400, 403, 422})
# GuardrailRaisedException's default wrapper and BlockedPiiEntityError, lowercased.
BLOCK_MESSAGES = ("guardrail raised an exception, guardrail: ", " by guardrail: ")
ERROR_TYPES = {BLOCKED: "MoyaiGuardrailBlocked", UNATTESTED: "MoyaiGuardrailUnattested"}
MESSAGES = {
    BLOCKED: "Your organization's AI guardrail blocked this request.",
    UNATTESTED: (
        "The model gateway did not confirm your organization's required AI guardrails, "
        "so this request was stopped."
    ),
}
ACTIONS = {BLOCKED: "ai_guardrail.violation", UNATTESTED: "ai_guardrail.unattested"}
# Turn workflows that see a guardrail denial publish its notice and keep its context out.
VERSION = "moyai-guardrail-failures-v1"


class GuardrailUnattested(RuntimeError):
    """Fixed message; the answer was refused before the SDK read any of it."""


@dataclass(frozen=True)
class Guardrail:
    outcome: str
    # Validated names from x-litellm-applied-guardrails.
    applied: tuple[str, ...] = ()
    # The refusing guardrail, when the gateway identified it.
    name: str | None = None
    mode: str | None = None
    # Required guardrails the answer did not attest.
    missing: tuple[str, ...] = ()

    def details(self, session_id: str, model: str) -> dict[str, Any]:
        """Audit metadata: guardrail names, mode, session and model only."""
        details: dict[str, Any] = {
            "session_id": session_id, "model": model, "guardrails": list(self.applied[:MAX_AUDIT_NAMES]),
        }
        if self.mode:
            details["mode"] = self.mode
        if self.missing:
            details["missing"] = list(self.missing[:MAX_AUDIT_NAMES])
        return details


def names(value: str | None) -> tuple[str, ...]:
    """LiteLLM joins names with commas; anything unexpected is dropped, not echoed."""
    found = (part.strip() for part in (value or "").split(",")[:MAX_NAMES])
    return tuple(dict.fromkeys(part for part in found if NAME.fullmatch(part)))


def blocked(status: int, applied_header: str | None, body: bytes) -> Guardrail | None:
    """The refusal a non-2xx gateway answer reports, if a guardrail refused it."""
    if status not in BLOCK_STATUSES:
        return None
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return None
    error = value.get("error") if isinstance(value, dict) else None
    if not isinstance(error, dict):
        return None
    fields = error.get("provider_specific_fields")
    fields = fields if isinstance(fields, dict) else {}
    reported = fields.get("guardrail_name")
    message = error.get("message")
    message = message.lower() if isinstance(message, str) else ""
    applied = names(applied_header)
    if isinstance(reported, str):
        name = reported if NAME.fullmatch(reported) else None
    else:
        # The name follows the wrapper. Only an attested name counts, the
        # longest when one name prefixes another (presidio-pii, presidio-pii.v2).
        named = next((message.split(wrapper, 1)[1] for wrapper in BLOCK_MESSAGES if wrapper in message), "")
        name = max((item for item in applied if re.match(
            re.escape(item.lower()) + r"(?![a-z0-9_:-])", named,
        )), key=len, default=None)
        if name is None:
            return None
    mode = fields.get("guardrail_mode")
    return Guardrail(BLOCKED, applied, name, mode if isinstance(mode, str) and NAME.fullmatch(mode) else None)


def unattested(applied_header: str | None, required: tuple[str, ...]) -> Guardrail | None:
    """A successful answer that does not attest every required guardrail."""
    applied = names(applied_header)
    missing = tuple(name for name in required if name not in applied)
    return Guardrail(UNATTESTED, applied, missing=missing) if missing else None


def denial(outcome: str) -> ApplicationError:
    """The typed, non-retryable activity failure for a guardrail outcome.

    A retry would send the refused input again, and the gateway's error can
    quote that input, so raise it from None to keep it out of the history.
    """
    return ApplicationError(MESSAGES[outcome], type=ERROR_TYPES[outcome], non_retryable=True)
