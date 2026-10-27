"""Activity audit rows (app.governance_activity) written from native transactions.

Native and canonical share one PostgreSQL database (authorize_admission checks
it), so rows go to the canonical governance_activity_events by qualified name.
The actor is resolved in the INSERT, as governance actor labels are: an
individual's email, a shared sign-in's label, otherwise the account id.

record() inserts in the caller's transaction: session and message activity
commits or rolls back with the change it describes (fails closed). refused()
records a policy denial in its own short transaction on the canonical pool, never
the native pool the caller's transaction holds, and takes no advisory lock: a
shared lock queued behind a waiting exclusive writer, while the caller holds its
own shared lock, would hang where PostgreSQL's deadlock detector cannot see it.
A denial whose write fails or times out is still enforced; the failure is
logged with the action only (fails open).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import text

log = logging.getLogger(__name__)
DETACHED_TIMEOUT = 2


class ProductActivityAudit:
    def __init__(self, identity: Any, engine: Any):
        from app.governance_activity import ACTIVITY_TABLE
        from app.identity_kinds import INDIVIDUAL_KINDS_SQL
        self.identity, self.engine = identity, engine
        self.insert = text(
            f"INSERT INTO {identity._table(ACTIVITY_TABLE)} (id,action,outcome,actor,actor_key,actor_id,"
            "resource_type,resource_id,session_id,client,details,created_at) "
            "SELECT :id,:action,:outcome,actor,lower(actor),:actor_id,:resource_type,:resource_id,:session_id,'',"
            ":details,:created_at FROM (SELECT COALESCE((SELECT email FROM "
            f"{identity._table('users')} WHERE id=:actor_id AND kind IN {INDIVIDUAL_KINDS_SQL} AND email<>''), "
            ":fallback) AS actor) resolved ON CONFLICT (id) DO NOTHING"
        )

    def _values(self, event) -> dict[str, Any]:
        from app.enterprise_roles import shared_label
        from app.governance_audit import timestamp
        return {**event._asdict(), "fallback": shared_label(event.actor_id) or event.actor_id or "system",
                "created_at": timestamp()}

    async def record(self, db: Any, action: str, **event: Any) -> None:
        """Insert one activity_event(action, **event) in the caller's transaction."""
        from app.governance_activity import activity_event
        await db.execute(self.insert, self._values(activity_event(action, **event)))

    async def refused(self, action: str, **event: Any) -> None:
        """Record one denial in a separate transaction within two seconds, or log that it was lost."""
        from app.governance_activity import activity_event
        try:
            values = self._values(activity_event(action, **event))
            async with asyncio.timeout(DETACHED_TIMEOUT), self.engine.begin() as connection:
                await connection.exec_driver_sql("SET LOCAL statement_timeout = '2s'")
                await connection.exec_driver_sql("SET LOCAL lock_timeout = '250ms'")
                await connection.execute(self.insert, values)
        except Exception as failure:  # noqa: BLE001 - the denial is enforced whether or not it is recorded.
            log.warning("Policy refusal %s was not recorded: %s", action, type(failure).__name__)
