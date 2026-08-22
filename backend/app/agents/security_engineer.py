"""
The Omni Security Engineer.

It runs a bounded retrieve-then-reason loop: the model may call the read-only
tools in `app.agents.tools` as many times as the iteration budget allows, every
call executes a real query against this organization's data, and the rows that
come back are the only material the answer may draw on. The draft is then
checked against the records that were actually returned, and withheld if it
names anything that was not.

What changed and why
--------------------
The previous implementation built a context string — "Total Assets: 41" plus
fifty finding titles — pasted it above the user's question, and returned the
model's completion directly as the answer. Three consequences followed from
that shape, and each is addressed structurally rather than by instruction:

* The model could only see what the context builder happened to include, so
  every question outside that shape was answered from parametric memory. Now it
  asks for what it needs and gets rows or an explicit "no records matched".
* Nothing distinguished a statement backed by a record from one that was not.
  Now every answer is validated against the retrieved evidence.
* When the LLM endpoint was unreachable, the exception text was returned in the
  answer field. Now an unreachable model is a status, not content.

Prompting is not the safety mechanism here — the tool boundary and the
grounding check are. The system prompt exists to make good behaviour likely,
not to be relied on.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.agents import actions as action_registry
from app.agents import grounding
from app.agents.provider import (
    LLMProvider, ProviderStatus, ProviderUnavailable, get_provider,
)
from app.agents.tools import ToolContext, ToolError, ToolResult, run_tool, tools_for
from app.core.config import settings
from app.models.agent import (
    AgentActionProposal, AgentConversation, AgentMessage, GroundingStatus, MessageRole,
)
from app.models.finding import Finding
from app.models.user import User

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the Omni Cyber Guard security engineer. You help an operator understand
the exposure data held in their own Omni Cyber Guard database.

HOW YOU WORK
You have no knowledge of this environment except what the tools return. Call
tools to retrieve records, then answer from those records. If you have not
retrieved something, you do not know it.

RULES
1. Never state a vulnerability, asset, address, hostname, CVE, score or count
   that a tool did not return in this conversation. There is an automated check
   for this and answers that fail it are withheld from the operator, so an
   invented detail costs them the whole answer.
2. If the tools return nothing relevant, say: "I do not have sufficient
   evidence to answer that." Then say which scan or synchronisation would
   produce the missing data. Never fill the gap from general knowledge.
3. An empty result means the database holds no such record. It does not mean
   the environment is secure. Say "not assessed", never "clean".
4. Respect what each record claims. A finding with confidence 'probable' is a
   version match, not a demonstrated vulnerability. An open port is an
   exposure, not a compromise. Never assert that anything has been exploited,
   breached or compromised; this platform does not run exploits and has no
   evidence of that kind.
5. Quote scanner evidence verbatim when it supports a point. Do not paraphrase
   it into a stronger claim than it makes.
6. You cannot change anything. To suggest a change, call propose_action, which
   records it for a human to confirm. Report it as proposed, never as done.
7. Cite the records you used, by identifier, so the operator can check you.
8. Be brief and concrete. No filler, no reassurance.
"""

ANALYSE_FINDING_INSTRUCTION = """\
Analyse the finding with identifier {finding_id}.

Retrieve it first with get_finding. Then, if it carries a CVE, look that CVE up
in the local intelligence store, and retrieve the affected asset for context.
Cover: what the evidence actually shows, how firmly (the finding's confidence
value), what it means for this specific asset given its criticality and
exposure, and what to do about it. If the intelligence store has no record of
the CVE, say so rather than describing it from memory.
"""


@dataclass
class ToolInvocation:
    name: str
    arguments: dict
    row_count: int
    error: str = ""

    def as_dict(self) -> dict:
        payload = {
            "tool": self.name,
            "arguments": self.arguments,
            "row_count": self.row_count,
        }
        if self.error:
            payload["error"] = self.error
        return payload


@dataclass
class AgentAnswer:
    """
    The full result of one request, including the parts that let a reader check it.

    `available` false means no model was reachable; `answer` is then empty and
    `provider_status` carries the explanation. There is deliberately no code
    path that puts an error message into `answer`.
    """
    available: bool
    answer: str = ""
    grounding: grounding.GroundingReport | None = None
    evidence_rows: list[dict] = field(default_factory=list)
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    proposals: list[AgentActionProposal] = field(default_factory=list)
    provider_status: ProviderStatus | None = None
    conversation_id: uuid.UUID | None = None
    message_id: uuid.UUID | None = None
    unavailable_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "available": self.available,
            "answer": self.answer,
            "unavailable_reason": self.unavailable_reason,
            "grounding": self.grounding.as_dict() if self.grounding else None,
            "evidence": self.evidence_rows,
            "tool_calls": [call.as_dict() for call in self.tool_calls],
            "conversation_id": str(self.conversation_id) if self.conversation_id else None,
            "message_id": str(self.message_id) if self.message_id else None,
            "provider": self.provider_status.as_dict() if self.provider_status else None,
        }


class SecurityEngineerAgent:
    def __init__(self, db: Session, user: User, provider: LLMProvider | None = None):
        self.db = db
        self.user = user
        self.provider = provider or get_provider()
        self.ctx = ToolContext(db=db, organization_id=user.organization_id, user=user)

    # -- public API ------------------------------------------------------

    def status(self) -> ProviderStatus:
        return self.provider.status()

    def retrieval_tools(self):
        """The retrievals this user's permissions allow. Used by /agent/status
        so an operator can see exactly what the assistant is able to read."""
        return tools_for(self.ctx)

    def ask(self, question: str, conversation: AgentConversation) -> AgentAnswer:
        question = (question or "").strip()
        if not question:
            raise ValueError("A question is required.")
        return self._run(
            conversation=conversation,
            user_content=question,
            instruction=question,
        )

    def analyze_finding(
        self, finding: Finding, conversation: AgentConversation
    ) -> AgentAnswer:
        return self._run(
            conversation=conversation,
            user_content=f"Analyse finding {finding.id} ({finding.title}).",
            instruction=ANALYSE_FINDING_INSTRUCTION.format(finding_id=finding.id),
        )

    # -- the loop --------------------------------------------------------

    def _run(
        self, *, conversation: AgentConversation, user_content: str, instruction: str
    ) -> AgentAnswer:
        provider_status = self.provider.status()
        self._record(conversation, MessageRole.USER, user_content)

        if not provider_status.configured:
            return AgentAnswer(
                available=False,
                provider_status=provider_status,
                conversation_id=conversation.id,
                unavailable_reason=(
                    "No language model is configured, so the security engineer "
                    "cannot compose an answer. Your data is unaffected — every "
                    "page that reads it directly continues to work."
                ),
            )

        available_tools = tools_for(self.ctx)
        schemas = [tool.schema() for tool in available_tools]
        if self._may_propose():
            schemas.append(action_registry.proposal_tool_schema())

        messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": instruction},
        ]

        evidence: set[str] = set()
        evidence_rows: list[dict] = []
        invocations: list[ToolInvocation] = []
        proposals: list[AgentActionProposal] = []
        retrieved_any = False
        draft = ""

        for iteration in range(settings.AGENT_MAX_TOOL_ITERATIONS):
            try:
                reply = self.provider.chat(messages, schemas)
            except ProviderUnavailable as exc:
                logger.warning("Security engineer could not reach the model: %s", exc)
                self._record(
                    conversation, MessageRole.ASSISTANT, "",
                    grounding_status=GroundingStatus.UNAVAILABLE,
                )
                return AgentAnswer(
                    available=False,
                    provider_status=provider_status,
                    conversation_id=conversation.id,
                    tool_calls=invocations,
                    evidence_rows=evidence_rows,
                    unavailable_reason=(
                        f"The configured model at {provider_status.endpoint} could "
                        f"not be reached: {exc}"
                    ),
                )

            if not reply.tool_calls:
                draft = reply.content or ""
                break

            assistant_turn: dict = {"role": "assistant", "content": reply.content or ""}
            assistant_turn["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(call.arguments),
                    },
                }
                for call in reply.tool_calls
            ]
            messages.append(assistant_turn)

            for call in reply.tool_calls:
                if call.name == "propose_action":
                    payload, proposal = self._handle_proposal(conversation, call.arguments)
                    if proposal is not None:
                        proposals.append(proposal)
                    invocations.append(
                        ToolInvocation(
                            name="propose_action", arguments=call.arguments,
                            row_count=0,
                            error="" if proposal is not None else payload.get("error", ""),
                        )
                    )
                    messages.append({
                        "role": "tool", "tool_call_id": call.id,
                        "name": call.name, "content": json.dumps(payload),
                    })
                    continue

                try:
                    result = run_tool(self.ctx, call.name, call.arguments)
                except ToolError as exc:
                    invocations.append(
                        ToolInvocation(call.name, call.arguments, 0, error=str(exc))
                    )
                    self._record(
                        conversation, MessageRole.TOOL, str(exc),
                        tool_name=call.name, tool_arguments=call.arguments, tool_row_count=0,
                    )
                    messages.append({
                        "role": "tool", "tool_call_id": call.id, "name": call.name,
                        "content": json.dumps({"error": str(exc)}),
                    })
                    continue

                self._absorb(result, evidence, evidence_rows)
                retrieved_any = retrieved_any or bool(result.rows)
                invocations.append(
                    ToolInvocation(call.name, call.arguments, len(result.rows))
                )
                payload = result.as_payload()
                self._record(
                    conversation, MessageRole.TOOL, json.dumps(payload)[:8000],
                    tool_name=call.name, tool_arguments=call.arguments,
                    tool_row_count=len(result.rows),
                )
                messages.append({
                    "role": "tool", "tool_call_id": call.id, "name": call.name,
                    "content": json.dumps(payload),
                })
        else:
            # The budget ran out with the model still asking for data. Rather
            # than let it answer from a partial picture without saying so, ask
            # for a final answer with tools withdrawn.
            try:
                draft = self.provider.chat(
                    messages + [{
                        "role": "user",
                        "content": (
                            "Answer now from what you have retrieved. Do not "
                            "request more data. State explicitly that your answer "
                            "is based on a partial retrieval."
                        ),
                    }],
                    [],
                ).content or ""
            except ProviderUnavailable as exc:
                return AgentAnswer(
                    available=False, provider_status=provider_status,
                    conversation_id=conversation.id, tool_calls=invocations,
                    evidence_rows=evidence_rows,
                    unavailable_reason=f"The model became unreachable mid-analysis: {exc}",
                )

        report = grounding.validate(draft, evidence, retrieved_any=retrieved_any)

        if report.accepted or report.status == GroundingStatus.NO_EVIDENCE:
            answer = draft if report.accepted else (
                draft or grounding.INSUFFICIENT_EVIDENCE
            )
            withheld = ""
        else:
            answer = grounding.rejection_notice(report)
            withheld = draft

        message = self._record(
            conversation, MessageRole.ASSISTANT, answer,
            evidence_refs=sorted(evidence),
            grounding_status=report.status,
            unsupported_refs=report.unsupported_refs,
            withheld_draft=withheld,
            provider=self.provider.name, model=self.provider.model,
        )
        for proposal in proposals:
            proposal.message_id = message.id
            self.db.add(proposal)
        self.db.flush()

        return AgentAnswer(
            available=True,
            answer=answer,
            grounding=report,
            evidence_rows=evidence_rows,
            tool_calls=invocations,
            proposals=proposals,
            provider_status=provider_status,
            conversation_id=conversation.id,
            message_id=message.id,
        )

    # -- helpers ---------------------------------------------------------

    def _may_propose(self) -> bool:
        held = self.ctx.permissions
        return any(
            action.required_permission.value in held for action in action_registry.ACTIONS
        )

    def _handle_proposal(
        self, conversation: AgentConversation, arguments: dict
    ) -> tuple[dict, AgentActionProposal | None]:
        try:
            proposal = action_registry.propose(
                self.db,
                organization_id=self.user.organization_id,
                action_type=str(arguments.get("action_type", "")),
                parameters=arguments.get("parameters") or {},
                rationale=str(arguments.get("rationale", "")),
                proposed_by_user_id=self.user.id,
                conversation_id=conversation.id,
            )
        except action_registry.ActionError as exc:
            return {
                "recorded": False,
                "error": str(exc),
                "note": "Nothing was proposed. Tell the operator why.",
            }, None

        return {
            "recorded": True,
            "proposal_id": str(proposal.id),
            "effect": proposal.effect_summary,
            "status": "awaiting human confirmation",
            "note": (
                "This has NOT been carried out. It is queued for an operator "
                "holding "
                f"{proposal.required_permission} to confirm or reject."
            ),
        }, proposal

    @staticmethod
    def _absorb(result: ToolResult, evidence: set[str], rows: list[dict]) -> None:
        evidence.update(result.refs)
        rows.extend(result.rows)

    def _record(
        self,
        conversation: AgentConversation,
        role: MessageRole,
        content: str,
        *,
        tool_name: str | None = None,
        tool_arguments: dict | None = None,
        tool_row_count: int | None = None,
        evidence_refs: list[str] | None = None,
        grounding_status: GroundingStatus = GroundingStatus.NOT_APPLICABLE,
        unsupported_refs: list[str] | None = None,
        withheld_draft: str = "",
        provider: str | None = None,
        model: str | None = None,
    ) -> AgentMessage:
        message = AgentMessage(
            organization_id=conversation.organization_id,
            conversation_id=conversation.id,
            role=role,
            content=content or "",
            tool_name=tool_name,
            tool_arguments=tool_arguments or {},
            tool_row_count=tool_row_count,
            evidence_refs=evidence_refs or [],
            grounding_status=grounding_status,
            unsupported_refs=unsupported_refs or [],
            withheld_draft=withheld_draft or "",
            provider=provider,
            model=model,
        )
        self.db.add(message)
        self.db.flush()
        return message
