"""Bounded failure context without provider payloads, credentials, or reasoning."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, ToolCallPart, ToolReturnPart
from sqlalchemy import select
from temporalio.exceptions import ActivityError, ApplicationError

from .history_handoff import is_turn_run, latest_turn_snapshot
from .inference_guardrails import ERROR_TYPES as GUARDRAIL_ERRORS
from .models import Event, Turn
from .presentation import private_tool, redact
from .progress import progress_secrets

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from .database import Database
    from .runtime import Runtime

FAILURE_KIND = "failure_diagnostics"
FAILURE_VERSION = "moyai-failure-diagnostics-v1"
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/-]{1,200}")
RESULT_LIMIT = 6_000
FAILURE_LIMIT = 5


def safe_failure_metadata(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """Whitelist metadata; exception messages and arbitrary provider details stay out."""
    if not isinstance(value, dict) or not isinstance(value.get("exception_chain"), list):
        return None
    chain = []
    for item in value["exception_chain"][:8]:
        if not isinstance(item, dict):
            continue
        safe = {
            key: item[key] for key in ("type", "application_type", "activity_type", "activity_id")
            if isinstance(item.get(key), str) and IDENTIFIER.fullmatch(item[key])
        }
        if "type" in safe:
            chain.append(safe)
    return {"exception_chain": chain} if chain else None


def capture_failure(error: BaseException) -> dict[str, Any] | None:
    chain, seen = [], set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen and len(chain) < 8:
        seen.add(id(current))
        item = {"type": type(current).__name__}
        if isinstance(current, ApplicationError) and current.type:
            item["application_type"] = current.type
        if isinstance(current, ActivityError):
            item["activity_type"] = current.activity_type
            item["activity_id"] = current.activity_id
        chain.append(item)
        cause = getattr(current, "cause", None) or current.__cause__
        if cause is None and not current.__suppress_context__:
            cause = current.__context__
        current = cause if isinstance(cause, BaseException) else None
    return safe_failure_metadata({"exception_chain": chain})


async def recorded_failure(database: Database, db: AsyncSession, turn: Turn) -> dict[str, Any] | None:
    recorded = await db.scalar(select(Event).where(
        Event.turn_id == turn.id, Event.kind == FAILURE_KIND,
    ).order_by(Event.id).limit(1))
    return safe_failure_metadata(json.loads(database.security.unseal(recorded.content))) if recorded else None


async def failure_summary(database: Database, db: AsyncSession, turn: Turn) -> str:
    """Only whitelisted runtime identifiers cross into parent context and cards."""
    metadata = await recorded_failure(database, db, turn)
    if not metadata:
        return "The subagent failed before completing its assignment. Open its conversation for failure details."
    chain = metadata["exception_chain"]
    cause = chain[-1].get("application_type", chain[-1]["type"])
    activity = next((item["activity_type"] for item in chain if item.get("activity_type")), None)
    return f"Subagent failed: {cause}" + (f" during {activity}" if activity else "") + ". Open its conversation for failure details."


def guardrail_outcome(metadata: dict[str, Any] | None) -> str | None:
    """The gateway guardrail outcome whose typed denial is in this failure chain."""
    outcomes = {kind: outcome for outcome, kind in GUARDRAIL_ERRORS.items()}
    return next((
        outcomes[item["application_type"]] for item in (metadata or {}).get("exception_chain", ())
        if item.get("application_type") in outcomes
    ), None)


async def guardrail_refused(database: Database, turn: Turn) -> bool:
    """Whether a gateway guardrail's typed denial failed this turn."""
    async with database.sessions() as db:
        return guardrail_outcome(await recorded_failure(database, db, turn)) is not None


async def failure_details(runtime: Runtime, turn: Turn) -> dict[str, Any]:
    secrets = progress_secrets(runtime, turn)
    async with runtime.database.sessions() as db:
        metadata = await recorded_failure(runtime.database, db, turn)
    notes = [] if metadata else ["Runtime exception details were not captured for this turn."]
    calls: dict[tuple[str, str], dict[str, Any]] = {}
    last_action = None
    observed_usage = {"requests": 0, "input_tokens": 0, "output_tokens": 0}
    failures = []
    history_error = False
    try:
        snapshot = await latest_turn_snapshot(runtime, turn.id, include_interrupted=True)
    except Exception:  # noqa: BLE001 - the failure record remains useful during history-store outages.
        snapshot = None
        history_error = True
        notes.append("Tool history is temporarily unavailable.")
    if snapshot is None and not history_error:
        notes.append("No saved tool history is available for this turn.")
    active_run = None
    for message in snapshot.messages if snapshot else []:
        if isinstance(message, ModelResponse):
            active_run = message.run_id if is_turn_run(message.run_id, turn.id) else None
            if active_run:
                observed_usage["requests"] += 1
                observed_usage["input_tokens"] += message.usage.input_tokens
                observed_usage["output_tokens"] += message.usage.output_tokens
                for part in message.parts:
                    if isinstance(part, ToolCallPart):
                        last_action = {
                            "id": part.tool_call_id, "tool": part.tool_name,
                            "timestamp": message.timestamp.isoformat() if message.timestamp else None,
                            "status": "interrupted",
                        }
                        calls[(active_run, part.tool_call_id)] = last_action
        elif isinstance(message, ModelRequest) and active_run:
            for part in message.parts:
                if not isinstance(part, (ToolReturnPart, RetryPromptPart)):
                    continue
                call = calls.get((active_run, part.tool_call_id or ""))
                if call is None or call["tool"] != part.tool_name:
                    continue
                failed = isinstance(part, RetryPromptPart) or getattr(part, "outcome", None) == "failed"
                call["status"] = "failed" if failed else "completed"
                if failed:
                    restricted = private_tool(part.tool_name)
                    content = None if restricted else (
                        part.content if isinstance(part.content, str)
                        else json.dumps(part.content, ensure_ascii=False, default=str)
                    )
                    content = str(redact(content, secrets)) if content is not None else None
                    failures.append({
                        **call, "timestamp": message.timestamp.isoformat() if message.timestamp else None,
                        "error": content[:RESULT_LIMIT] if content is not None else None,
                        "restricted": restricted, "truncated": content is not None and len(content) > RESULT_LIMIT,
                    })
    usage = json.loads(turn.usage)
    usage_view = observed_usage.copy() if observed_usage["input_tokens"] or observed_usage["output_tokens"] else {}
    usage_view.update({
        key: usage[key] for key in ("requests", "input_tokens", "output_tokens")
        if isinstance(usage, dict) and isinstance(usage.get(key), (int, float))
    })
    return redact({
        "session_id": turn.session_id, "turn_id": turn.id, "workflow_id": turn.workflow_id,
        "status": turn.status, "model": turn.model, "summary": turn.error,
        "created_at": turn.created_at, "finished_at": turn.finished_at,
        "runtime": metadata, "notes": notes,
        "last_action": last_action,
        "recent_failures": failures[-FAILURE_LIMIT:],
        "failures_limited": len(failures) > FAILURE_LIMIT,
        "usage": usage_view,
    }, secrets)
