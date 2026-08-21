"""
The scanner adapter contract.

Every assessment tool the platform can drive implements this interface. The
point of a formal contract is not tidiness — it is that the orchestrator can
treat a local subprocess, a remote scanner API and a credentialed agent
identically, and that a tool which is not installed produces "integration not
configured" instead of nothing, or worse, invented results.

Three obligations are non-negotiable for any implementation:

1. `validate_configuration()` must tell the truth about whether the tool can
   actually run, and say what is missing when it cannot. An adapter that
   hardcodes "available" is the exact failure this platform removed in Phase 1.
2. `normalize_results()` must derive every field from real tool output. If the
   tool did not report a CVE, the adapter does not invent one.
3. Every finding must carry `confidence` reflecting what the tool actually
   established. A version banner is PROBABLE evidence, not CONFIRMED.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class ScannerCapability(str, Enum):
    """What an adapter can genuinely do.

    Declared rather than assumed, so the orchestrator can pick a tool for a job
    and the UI can explain why a scan type is unavailable.
    """
    HOST_DISCOVERY = "host_discovery"
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    OS_DETECTION = "os_detection"
    WEB_ASSESSMENT = "web_assessment"
    CONFIGURATION_AUDIT = "configuration_audit"
    CREDENTIALED = "credentialed"
    TLS_ASSESSMENT = "tls_assessment"


class SessionState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class ConfigurationStatus:
    """Whether this adapter can run, and what to do if it cannot."""

    available: bool
    #: One line suitable for display in the UI.
    summary: str
    #: Concrete remediation, e.g. "apt-get install nmap" or "set GVM_API_URL".
    remediation: str = ""
    #: Version string of the underlying tool, when it can be determined.
    tool_version: str | None = None

    @classmethod
    def ready(cls, summary: str, tool_version: str | None = None) -> "ConfigurationStatus":
        return cls(available=True, summary=summary, tool_version=tool_version)

    @classmethod
    def not_configured(cls, summary: str, remediation: str) -> "ConfigurationStatus":
        return cls(available=False, summary=summary, remediation=remediation)


@dataclass
class TargetValidation:
    """Whether this adapter accepts a target, with a reason when it does not."""

    valid: bool
    reason: str = ""
    #: The target rewritten into the form the tool expects, when applicable.
    normalized_target: str | None = None


@dataclass
class ScanCredential:
    """
    Credential material handed to an adapter for one scan.

    Deliberately a plain dataclass with a redacting repr: it must never be
    serialised into a response, a log line or a traceback.
    """
    credential_type: str
    username: str = ""
    domain: str = ""
    secret: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return f"<ScanCredential {self.credential_type} user={self.username!r} secret=***>"

    __str__ = __repr__


@dataclass
class ScanRequest:
    """Everything an adapter needs to run one assessment."""

    target: str
    #: Optional credential for authenticated assessment.
    credential: ScanCredential | None = None
    #: Adapter-specific options, validated by the adapter itself.
    options: dict[str, Any] = field(default_factory=dict)
    #: Wall-clock budget. An adapter that cannot honour it must say so in
    #: validate_configuration rather than running indefinitely.
    timeout_seconds: int = 600


@dataclass
class ScanSession:
    """A running scan. Opaque to the orchestrator apart from its handle."""

    handle: str
    adapter: str
    target: str
    started_at: datetime
    #: Adapter-owned state — a Popen object, a remote job ID, a task handle.
    context: Any = None

    @classmethod
    def new(cls, adapter: str, target: str, context: Any = None) -> "ScanSession":
        return cls(
            handle=uuid.uuid4().hex,
            adapter=adapter,
            target=target,
            started_at=datetime.now(timezone.utc),
            context=context,
        )


@dataclass
class ScanProgress:
    """A point-in-time view of a running scan."""

    state: SessionState
    #: 0-100 where the tool reports it. None where it genuinely cannot be
    #: known — a fabricated percentage is worse than an honest "unknown".
    percent_complete: float | None = None
    message: str = ""
    error: str | None = None

    @property
    def finished(self) -> bool:
        return self.state in (SessionState.COMPLETED, SessionState.FAILED, SessionState.CANCELED)


@dataclass
class NormalizedFinding:
    """
    A finding in the platform's own shape, independent of which tool produced it.

    `identifier` is the stable check identity used for deduplication — a CVE ID,
    an nmap script ID, a nuclei template ID. `location` distinguishes the same
    defect on different ports or URLs.
    """

    title: str
    severity: str
    finding_class: str
    confidence: str
    identifier: str
    location: str = ""
    description: str = ""
    #: Verbatim tool output. Never paraphrased.
    evidence: str = ""
    remediation_guidance: str = ""
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_product: str | None = None
    affected_version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "finding_class": self.finding_class,
            "confidence": self.confidence,
            "check_id": self.identifier,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "remediation_guidance": self.remediation_guidance,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "affected_product": self.affected_product,
            "affected_version": self.affected_version,
        }


@dataclass
class ScannerResult:
    """The outcome of one completed scan."""

    target: str
    scanner_name: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    #: Structured host data for discovery scanners; empty for the rest.
    raw_data: Any = None
    hosts_discovered: int = 0
    error: str | None = None

    @property
    def findings_generated(self) -> int:
        return len(self.findings)


ProgressCallback = Callable[[str], None]


class ScannerAdapter(ABC):
    """
    Contract every scanner integration implements.

    Lifecycle:

        status = adapter.validate_configuration()
        if not status.available: -> report status.remediation, do not scan

        validation = adapter.validate_target(target)
        if not validation.valid: -> report validation.reason

        session = adapter.start_scan(request)
        while not adapter.get_status(session).finished:
            ...                                    # poll; cancel if asked
        result = adapter.get_results(session)
    """

    # --- identity ---------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier used as the finding `source` and the engine key."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Version of this adapter, not of the underlying tool."""

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[ScannerCapability]:
        """What this adapter can actually do."""

    @property
    def description(self) -> str:
        return ""

    @property
    def requires_credential(self) -> bool:
        return ScannerCapability.CREDENTIALED in self.capabilities

    # --- configuration ----------------------------------------------------

    @abstractmethod
    def validate_configuration(self) -> ConfigurationStatus:
        """
        Report whether this adapter can run right now.

        Must probe something real — the presence of a binary, a reachable API,
        an importable library. Returning a hardcoded `available=True` makes
        every downstream guarantee in the platform false.
        """

    @abstractmethod
    def validate_target(self, target: str) -> TargetValidation:
        """Report whether this adapter accepts the target, and why not if it does not."""

    def is_available(self) -> bool:
        """Convenience wrapper retained for callers that only need the boolean."""
        return self.validate_configuration().available

    # --- execution --------------------------------------------------------

    @abstractmethod
    def start_scan(self, request: ScanRequest, on_output: ProgressCallback | None = None) -> ScanSession:
        """Begin a scan and return immediately with a session handle."""

    @abstractmethod
    def get_status(self, session: ScanSession) -> ScanProgress:
        """Report the current state of a running scan."""

    @abstractmethod
    def get_results(self, session: ScanSession) -> ScannerResult:
        """
        Return the results of a finished scan.

        Must raise if called before the session has finished, rather than
        returning partial results that would read as complete.
        """

    @abstractmethod
    def cancel_scan(self, session: ScanSession) -> bool:
        """
        Stop a running scan for real and report whether it was stopped.

        An implementation that returns True without terminating anything makes
        the platform report an outcome that did not happen.
        """

    # --- normalization ----------------------------------------------------

    @abstractmethod
    def normalize_results(self, raw: Any) -> list[NormalizedFinding]:
        """Convert this tool's native output into the platform's finding shape."""
