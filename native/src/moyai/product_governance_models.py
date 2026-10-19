"""Native execution bindings for canonical governance; importing performs no I/O.

Policy configuration stays in the canonical schema. This module holds only what
a native session pins at creation, so later profile edits cannot widen it.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base, now


class ProductSessionPolicy(Base):
    """The security profile snapshot bound when a product session is created.

    Immutable on PostgreSQL: a v23 trigger rejects every UPDATE and DELETE.
    Execution intersects this binding with the current mandatory profile, so
    later governance changes can narrow a session's policy but never widen it.
    """

    __tablename__ = "moyai_product_session_policies"

    session_id: Mapped[str] = mapped_column(ForeignKey("moyai_sessions.id"), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(64))  # Empty when no profile applied.
    profile_revision: Mapped[int] = mapped_column(Integer)
    policy: Mapped[str] = mapped_column(Text)  # Canonical JSON of the bound profile policy.
    inherited_from: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
