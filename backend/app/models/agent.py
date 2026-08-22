"""
Persistence for the AI security engineer.

Three tables, and the reason each exists:

`agent_conversations` and `agent_messages` keep the transcript. That is not a
convenience feature. An assistant that comments on security posture is making
assertions an operator may act on, so the assertions have to be reviewable
after the fact — including which database records were retrieved to support
them and whether the answer passed grounding validation.

`agent_action_proposals` is the gate. The agent's retrieval tools are read-only
by construction; it cannot change anything. When it concludes that something
should be done it records a proposal, and a human with the permission that
action requires confirms it. The proposal stores the exact parameters that will
be executed, so what is confirmed is what runs.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class MessageRole(str, PyEnum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"


class GroundingStatus(str, PyEnum):
    """
    The outcome of checking an answer against the records actually retrieved.

    NOT_APPLICABLE is used for user and tool messages, which make no claims of
    their own.
    """
    # Every identifier the answer names appears in the retrieved evidence.
    GROUNDED = "grounded"
    # The answer named a record, CVE or address that no tool returned. The
    # text is retained for audit but is not presented as analysis.
    REJECTED = "rejected"
    # No tool returned any record, so there is nothing to reason from.
    NO_EVIDENCE = "no_evidence"
    # The model could not be reached, or refused.
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class ProposalStatus(str, PyEnum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    EXPIRED = "expired"


OPEN_PROPOSAL_STATUSES = frozenset({ProposalStatus.PROPOSED})
TERMINAL_PROPOSAL_STATUSES = frozenset({
    ProposalStatus.REJECTED, ProposalStatus.EXECUTED,
    ProposalStatus.FAILED, ProposalStatus.EXPIRED,
})


class AgentConversation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_conversations"
    __table_args__ = (
        Index("ix_agent_conversations_org_user", "organization_id", "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), default="", server_default="")

    messages: Mapped[list["AgentMessage"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan",
        order_by="AgentMessage.created_at",
    )


class AgentMessage(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_messages"
    __table_args__ = (
        Index("ix_agent_messages_conversation", "conversation_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_conversations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    role: Mapped[MessageRole] = mapped_column(Enum(MessageRole), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", server_default="")

    # Set on TOOL messages: which retrieval ran, with what arguments, and how
    # many rows came back.
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool_arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Set on ASSISTANT messages: the record references the answer was checked
    # against, and the result of that check.
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    grounding_status: Mapped[GroundingStatus] = mapped_column(
        Enum(GroundingStatus), default=GroundingStatus.NOT_APPLICABLE,
        server_default="NOT_APPLICABLE",
    )
    unsupported_refs: Mapped[list] = mapped_column(JSON, default=list)
    # A rejected draft is kept here, never in `content`. It is evidence about
    # the model's behaviour, not analysis, and the API does not return it to
    # ordinary callers.
    withheld_draft: Mapped[str] = mapped_column(Text, default="", server_default="")

    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    conversation: Mapped["AgentConversation"] = relationship(back_populates="messages")


class AgentActionProposal(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_action_proposals"
    __table_args__ = (
        Index("ix_agent_proposals_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_conversations.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    message_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_messages.id", ondelete="SET NULL"), nullable=True
    )

    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    rationale: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Human-readable statement of exactly what confirming this will do, built
    # by the action definition rather than by the model.
    effect_summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    required_permission: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[ProposalStatus] = mapped_column(
        Enum(ProposalStatus), default=ProposalStatus.PROPOSED, server_default="PROPOSED"
    )
    proposed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, default="", server_default="")

    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
