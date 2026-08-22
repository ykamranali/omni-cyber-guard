"""
The retrieve-then-reason loop, and the confirmation gate on actions.

A scripted provider stands in for the language model so the loop's behaviour
can be tested against every response a real model might produce: a well-behaved
answer, a fabricated one, a refusal to stop calling tools, and a dead endpoint.
No network is involved and no model is required.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import requires_db

from app.agents import actions as action_registry
from app.agents.provider import LLMReply, ProviderStatus, ProviderUnavailable, ToolCall
from app.agents.security_engineer import SecurityEngineerAgent
from app.core.rbac import RoleName
from app.core.security import hash_password
from app.models.agent import (
    AgentConversation, AgentMessage, GroundingStatus, MessageRole, ProposalStatus,
)
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.remediation import RemediationStatus, RemediationTask
from app.models.user import User
from app.services.finding_identity import compute_fingerprint
from app.services.org_provisioning import provision_new_organization


class ScriptedProvider:
    """Replays a fixed list of replies, recording what it was asked."""

    name = "scripted"
    model = "scripted-model"

    def __init__(self, replies, configured=True, raises=None):
        self._replies = list(replies)
        self._configured = configured
        self._raises = raises
        self.calls: list[tuple[list[dict], list[dict]]] = []

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            configured=self._configured, provider=self.name,
            endpoint="scripted://", model=self.model,
            missing=[] if self._configured else ["AGENT_LLM_PROVIDER"],
        )

    def chat(self, messages, tools):
        self.calls.append((list(messages), list(tools)))
        if self._raises is not None:
            raise self._raises
        if not self._replies:
            return LLMReply(content="")
        return self._replies.pop(0)


_ROLES: dict = {}


def _user(db, organization, role_name: RoleName = RoleName.ORG_ADMIN) -> User:
    key = (id(db), organization.id)
    if key not in _ROLES:
        _ROLES[key] = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
        is_active=True,
    )
    user.roles = [_ROLES[key][role_name.value]]
    db.add(user)
    db.flush()
    return user


def _conversation(db, organization, user) -> AgentConversation:
    conversation = AgentConversation(
        organization_id=organization.id, user_id=user.id, title="test"
    )
    db.add(conversation)
    db.flush()
    return conversation


def _finding(db, organization, asset, **overrides) -> Finding:
    values = dict(
        organization_id=organization.id,
        asset_id=asset.id,
        title="Telnet is exposed on the management interface",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        source="nmap",
        cve_id=None,
        evidence="23/tcp open telnet",
    )
    values.update(overrides)
    values["fingerprint"] = compute_fingerprint(
        asset_id=asset.id, finding_class=values["finding_class"],
        source=values["source"], identifier=values.get("cve_id") or values["title"],
        location="23/tcp",
    )
    record = Finding(**values)
    db.add(record)
    db.flush()
    return record


@requires_db
class TestUnavailableModel:
    def test_an_unconfigured_model_is_a_status_not_an_answer(
        self, db, organization
    ):
        """
        The regression this locks down: the previous implementation returned
        "Error: Unable to reach the LLM provider…" in the answer field, which
        the UI rendered exactly where analysis goes.
        """
        user = _user(db, organization)
        agent = SecurityEngineerAgent(
            db, user, provider=ScriptedProvider([], configured=False)
        )
        answer = agent.ask("What is my riskiest host?", _conversation(db, organization, user))

        assert answer.available is False
        assert answer.answer == ""
        assert "No language model is configured" in answer.unavailable_reason
        assert answer.provider_status.missing

    def test_an_unreachable_model_produces_no_content(self, db, organization):
        user = _user(db, organization)
        agent = SecurityEngineerAgent(
            db, user,
            provider=ScriptedProvider([], raises=ProviderUnavailable("connection refused")),
        )
        answer = agent.ask("Anything critical?", _conversation(db, organization, user))

        assert answer.available is False
        assert answer.answer == ""
        assert "connection refused" in answer.unavailable_reason


@requires_db
class TestGroundedLoop:
    def test_the_model_is_offered_tools_not_a_context_dump(self, db, organization):
        user = _user(db, organization)
        provider = ScriptedProvider([LLMReply(content="Nothing to report.")])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        agent.ask("How many findings?", _conversation(db, organization, user))

        messages, tools = provider.calls[0]
        offered = {tool["function"]["name"] for tool in tools}
        assert "search_findings" in offered
        assert "count_findings" in offered
        # The question is passed through; nothing is pre-loaded into the prompt.
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert "How many findings?" in messages[1]["content"]

    def test_a_tool_call_runs_a_real_query_and_grounds_the_answer(
        self, db, organization, asset
    ):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "search_findings", {"limit": 5})]),
            LLMReply(content=f"{asset.hostname} has an exposed telnet service ({finding.id})."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("What is exposed?", _conversation(db, organization, user))

        assert answer.available is True
        assert answer.grounding.status is GroundingStatus.GROUNDED
        assert str(finding.id) in answer.answer
        assert answer.tool_calls[0].name == "search_findings"
        assert answer.tool_calls[0].row_count == 1
        assert answer.evidence_rows[0]["ref"] == f"finding:{finding.id}"

    def test_a_fabricated_cve_is_withheld_from_the_operator(
        self, db, organization, asset
    ):
        _finding(db, organization, asset)
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "search_findings", {})]),
            LLMReply(content="You are exposed to CVE-2021-44228 on this host."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("What is exposed?", _conversation(db, organization, user))

        assert answer.grounding.status is GroundingStatus.REJECTED
        assert "CVE-2021-44228" in answer.grounding.unsupported_refs[0]
        # The operator is told the answer was withheld, and does not receive it.
        assert "withheld" in answer.answer
        assert "You are exposed to" not in answer.answer

    def test_a_withheld_draft_is_kept_for_review_but_not_returned(
        self, db, organization, asset
    ):
        _finding(db, organization, asset)
        user = _user(db, organization)
        conversation = _conversation(db, organization, user)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "search_findings", {})]),
            LLMReply(content="CVE-2021-44228 is present."),
        ])
        SecurityEngineerAgent(db, user, provider=provider).ask("What is exposed?", conversation)

        message = db.query(AgentMessage).filter(
            AgentMessage.conversation_id == conversation.id,
            AgentMessage.role == MessageRole.ASSISTANT,
        ).one()
        assert message.withheld_draft == "CVE-2021-44228 is present."
        assert "CVE-2021-44228 is present." not in message.content

    def test_an_answer_with_no_retrieval_behind_it_is_refused(self, db, organization):
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(content="Your network has three critical vulnerabilities on srv-app-02."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("How am I doing?", _conversation(db, organization, user))

        assert answer.grounding.status is GroundingStatus.REJECTED
        # The claim itself is not shown. The invented identifier is named, as
        # the reason for withholding — that is a report of the failure, not the
        # assessment.
        assert "three critical vulnerabilities" not in answer.answer
        assert "withheld" in answer.answer
        assert "host:srv-app-02" in answer.grounding.unsupported_refs

    def test_saying_there_is_no_data_is_permitted(self, db, organization):
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "count_findings", {"group_by": "severity"})]),
            LLMReply(content="No assessment has run yet, so there is nothing to report."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("How am I doing?", _conversation(db, organization, user))

        assert answer.grounding.status is GroundingStatus.NO_EVIDENCE
        assert "nothing to report" in answer.answer

    def test_a_tool_error_is_returned_to_the_model_not_to_the_operator(
        self, db, organization, asset
    ):
        _finding(db, organization, asset)
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "search_findings", {"severity": "nonsense"})]),
            LLMReply(tool_calls=[ToolCall("c2", "search_findings", {"severity": "high"})]),
            LLMReply(content="One high-severity exposure was found."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("Anything high?", _conversation(db, organization, user))

        assert answer.tool_calls[0].error
        assert "nonsense" not in answer.answer
        assert answer.available is True

    def test_the_iteration_budget_is_enforced(self, db, organization, asset):
        from app.core.config import settings

        _finding(db, organization, asset)
        user = _user(db, organization)
        # A model that never stops asking for data.
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall(f"c{index}", "search_findings", {})])
            for index in range(settings.AGENT_MAX_TOOL_ITERATIONS + 5)
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        agent.ask("Tell me everything.", _conversation(db, organization, user))

        # One call per iteration, plus the final tools-withdrawn request.
        assert len(provider.calls) == settings.AGENT_MAX_TOOL_ITERATIONS + 1
        assert provider.calls[-1][1] == []

    def test_the_transcript_records_which_retrievals_ran(
        self, db, organization, asset
    ):
        _finding(db, organization, asset)
        user = _user(db, organization)
        conversation = _conversation(db, organization, user)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[ToolCall("c1", "count_findings", {"group_by": "severity"})]),
            LLMReply(content="One high-severity item is open."),
        ])
        SecurityEngineerAgent(db, user, provider=provider).ask("Summary?", conversation)

        tool_messages = db.query(AgentMessage).filter(
            AgentMessage.conversation_id == conversation.id,
            AgentMessage.role == MessageRole.TOOL,
        ).all()
        assert [message.tool_name for message in tool_messages] == ["count_findings"]
        assert tool_messages[0].tool_arguments == {"group_by": "severity"}


@requires_db
class TestActionGate:
    def test_the_agent_cannot_change_anything_directly(
        self, db, organization, asset
    ):
        """A proposal is recorded; no remediation task exists until confirmed."""
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        provider = ScriptedProvider([
            LLMReply(tool_calls=[
                ToolCall("c1", "propose_action", {
                    "action_type": "create_remediation_task",
                    "parameters": {"finding_id": str(finding.id)},
                    "rationale": "Telnet is cleartext.",
                }),
            ]),
            LLMReply(content="I have proposed opening a remediation task."),
        ])
        agent = SecurityEngineerAgent(db, user, provider=provider)
        answer = agent.ask("What should I do?", _conversation(db, organization, user))

        assert len(answer.proposals) == 1
        proposal = answer.proposals[0]
        assert proposal.status is ProposalStatus.PROPOSED
        assert db.query(RemediationTask).count() == 0

    def test_the_effect_summary_is_written_by_the_platform_not_the_model(
        self, db, organization, asset
    ):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="whatever the model said",
            proposed_by_user_id=user.id,
        )
        assert finding.title in proposal.effect_summary
        assert "not marked resolved" in proposal.effect_summary

    def test_confirming_creates_the_task(self, db, organization, asset):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )
        action_registry.confirm(db, proposal, user)

        assert proposal.status is ProposalStatus.EXECUTED
        task = db.query(RemediationTask).one()
        assert str(task.finding_id) == str(finding.id)
        assert task.status is not RemediationStatus.VERIFIED
        assert proposal.result["remediation_task_id"] == str(task.id)

    def test_confirming_requires_the_actions_permission(
        self, db, organization, asset
    ):
        finding = _finding(db, organization, asset)
        proposer = _user(db, organization)
        viewer = _user(db, organization, RoleName.READ_ONLY)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=proposer.id,
        )

        with pytest.raises(action_registry.ActionError, match="manage_findings"):
            action_registry.confirm(db, proposal, viewer)
        assert db.query(RemediationTask).count() == 0

    def test_a_proposal_cannot_be_confirmed_twice(self, db, organization, asset):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )
        action_registry.confirm(db, proposal, user)

        with pytest.raises(action_registry.ActionError, match="already executed"):
            action_registry.confirm(db, proposal, user)
        assert db.query(RemediationTask).count() == 1

    def test_an_expired_proposal_is_refused(self, db, organization, asset):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )
        proposal.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.add(proposal)
        db.flush()

        with pytest.raises(action_registry.ActionError, match="expired"):
            action_registry.confirm(db, proposal, user)
        assert proposal.status is ProposalStatus.EXPIRED
        assert db.query(RemediationTask).count() == 0

    def test_preconditions_are_rechecked_at_confirmation_time(
        self, db, organization, asset
    ):
        """
        The world can change between proposing and confirming. A finding
        accepted as a risk in the meantime must not acquire remediation work.
        """
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )

        finding.status = FindingStatus.ACCEPTED_RISK
        db.add(finding)
        db.flush()

        with pytest.raises(action_registry.ActionError, match="nothing to remediate"):
            action_registry.confirm(db, proposal, user)
        assert proposal.status is ProposalStatus.FAILED
        assert db.query(RemediationTask).count() == 0

    def test_a_proposal_for_another_organizations_finding_is_refused(
        self, db, organization, second_organization, asset
    ):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)

        with pytest.raises(action_registry.ActionError, match="No finding"):
            action_registry.propose(
                db, organization_id=second_organization.id,
                action_type="create_remediation_task",
                parameters={"finding_id": str(finding.id)},
                rationale="Cross-tenant attempt.",
                proposed_by_user_id=user.id,
            )

    def test_rejecting_a_proposal_leaves_the_platform_unchanged(
        self, db, organization, asset
    ):
        finding = _finding(db, organization, asset)
        user = _user(db, organization)
        proposal = action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )
        action_registry.reject(db, proposal, user, note="Handled by the network team.")

        assert proposal.status is ProposalStatus.REJECTED
        assert proposal.decision_note == "Handled by the network team."
        assert db.query(RemediationTask).count() == 0

    def test_risk_acceptance_is_not_an_action_the_agent_can_propose(self):
        """
        Suppressing a finding for a period is a decision a person owns. It is
        deliberately absent from the registry, not merely discouraged.
        """
        assert "accept_risk" not in action_registry.ACTIONS_BY_TYPE
        assert "risk_acceptance" not in action_registry.ACTIONS_BY_TYPE
        assert set(action_registry.ACTIONS_BY_TYPE) == {
            "create_remediation_task", "assign_remediation_task",
        }

    def test_the_proposal_tool_tells_the_model_it_has_not_acted(self):
        description = action_registry.proposal_tool_schema()["function"]["description"]
        assert "does NOT perform" in description
        assert "never that you have done it" in description
