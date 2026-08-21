"""
Credentialed Windows configuration audit over WinRM.

This adapter reads settings; it never changes them. Each check runs a single
read-only PowerShell cmdlet and records the value it returned as evidence, so
every finding can be traced to the exact query that produced it.

Credentials arrive as a `ScanCredential` resolved from the vault immediately
before the scan and are never persisted or logged by this module.

This is not a subprocess adapter — it talks to a remote host over WinRM — so it
implements the session contract directly, running the checks on a worker thread
so `start_scan` returns and `cancel_scan` can interrupt between checks.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from app.scanners.contract import (
    ConfigurationStatus, NormalizedFinding, ProgressCallback, ScanProgress, ScanRequest,
    ScanSession, ScannerAdapter, ScannerCapability, ScannerResult, SessionState,
    TargetValidation,
)

logger = logging.getLogger(__name__)


@dataclass
class _Check:
    check_id: str
    title: str
    description: str
    severity: str
    #: Read-only PowerShell expression.
    query: str
    #: The returned value that indicates a problem.
    failure_value: str
    remediation: str


# Every query below is a read. None of them modify the target.
CHECKS: list[_Check] = [
    _Check(
        check_id="defender-disabled",
        title="Windows Defender anti-malware service is disabled",
        description="The real-time anti-malware service is not running on this host.",
        severity="high",
        query="(Get-MpComputerStatus).AMServiceEnabled",
        failure_value="false",
        remediation="Re-enable Microsoft Defender, or confirm an approved third-party AV is managing this host.",
    ),
    _Check(
        check_id="smbv1-enabled",
        title="SMBv1 protocol is enabled",
        description=(
            "The legacy SMBv1 protocol is enabled. It has a long history of remotely "
            "exploitable flaws and is widely used for lateral movement."
        ),
        severity="critical",
        query="(Get-SmbServerConfiguration).EnableSMB1Protocol",
        failure_value="true",
        remediation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
    ),
    _Check(
        check_id="rdp-nla-disabled",
        title="RDP Network Level Authentication is disabled",
        description=(
            "NLA is disabled for Remote Desktop, so a session is established before the "
            "user authenticates, widening the pre-authentication attack surface."
        ),
        severity="high",
        query=(
            "(Get-WmiObject -Class Win32_TSGeneralSetting "
            "-Namespace root\\cimv2\\terminalservices "
            "-Filter \"TerminalName='RDP-tcp'\").UserAuthenticationRequired"
        ),
        failure_value="0",
        remediation="Enable Network Level Authentication for Remote Desktop via Group Policy.",
    ),
    _Check(
        check_id="firewall-domain-off",
        title="Domain profile firewall is disabled",
        description="The Windows Firewall is turned off for the domain profile.",
        severity="high",
        query="(Get-NetFirewallProfile -Profile Domain).Enabled",
        failure_value="false",
        remediation="Enable the domain firewall profile: Set-NetFirewallProfile -Profile Domain -Enabled True",
    ),
    _Check(
        check_id="autologon-enabled",
        title="Automatic logon is configured",
        description=(
            "AutoAdminLogon is enabled, which typically means a password is stored in "
            "the registry in cleartext."
        ),
        severity="high",
        query=(
            "(Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon"
        ),
        failure_value="1",
        remediation="Disable automatic logon and remove any stored DefaultPassword value.",
    ),
]


@dataclass
class _AuditContext:
    request: ScanRequest
    thread: threading.Thread | None = None
    findings: list[NormalizedFinding] = field(default_factory=list)
    error: str | None = None
    canceled: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    progress_message: str = ""


class WindowsAuditScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "windows_audit"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def description(self) -> str:
        return "Credentialed Windows security configuration audit over WinRM."

    @property
    def capabilities(self) -> frozenset[ScannerCapability]:
        return frozenset({
            ScannerCapability.CONFIGURATION_AUDIT,
            ScannerCapability.CREDENTIALED,
        })

    # --- configuration ----------------------------------------------------

    def validate_configuration(self) -> ConfigurationStatus:
        try:
            import winrm  # noqa: F401
        except ImportError:
            return ConfigurationStatus.not_configured(
                summary="The 'pywinrm' library is not installed on this worker.",
                remediation="Install it with: pip install pywinrm",
            )
        return ConfigurationStatus.ready(summary="pywinrm is available.")

    def validate_target(self, target: str) -> TargetValidation:
        import ipaddress

        candidate = (target or "").strip()
        if not candidate:
            return TargetValidation(valid=False, reason="No target host supplied.")

        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return TargetValidation(valid=True, normalized_target=candidate)

        if not (address.is_private or address.is_loopback):
            return TargetValidation(
                valid=False,
                reason=(
                    f"Refusing to authenticate against {candidate}: it is not a private or "
                    f"loopback address."
                ),
            )
        return TargetValidation(valid=True, normalized_target=candidate)

    # --- execution --------------------------------------------------------

    def start_scan(self, request: ScanRequest, on_output: ProgressCallback | None = None) -> ScanSession:
        status = self.validate_configuration()
        if not status.available:
            raise RuntimeError(f"{status.summary} {status.remediation}".strip())

        validation = self.validate_target(request.target)
        if not validation.valid:
            raise ValueError(validation.reason)

        if request.credential is None:
            raise ValueError(
                "A credentialed Windows audit requires a credential profile. Select one in "
                "the Scan Center, or add one under Administration → Credentials."
            )

        context = _AuditContext(request=request)
        session = ScanSession.new(adapter=self.name, target=validation.normalized_target or request.target,
                                  context=context)

        def run() -> None:
            try:
                self._run_checks(session, context, on_output)
            except Exception as exc:  # noqa: BLE001
                # The message must never contain the credential.
                context.error = f"Windows audit failed: {type(exc).__name__}: {exc}"[:2000]
                logger.exception("windows_audit: run failed for %s", session.target)
            finally:
                context.done.set()

        context.thread = threading.Thread(target=run, daemon=True, name="ocg-windows-audit")
        context.thread.start()
        return session

    def _run_checks(self, session: ScanSession, context: _AuditContext,
                    on_output: ProgressCallback | None) -> None:
        import winrm

        credential = context.request.credential
        username = (
            f"{credential.domain}\\{credential.username}" if credential.domain else credential.username
        )
        transport = context.request.options.get("transport", "ntlm")

        connection = winrm.Session(
            session.target, auth=(username, credential.secret), transport=transport
        )

        for check in CHECKS:
            if context.canceled.is_set():
                return

            context.progress_message = f"Checking {check.check_id}"
            if on_output:
                on_output(f"[windows_audit] {check.title}")

            try:
                response = connection.run_ps(check.query)
            except Exception as exc:  # noqa: BLE001
                # A check that did not run is recorded as not-assessed, never as passed.
                context.findings.append(NormalizedFinding(
                    title=f"Check '{check.check_id}' could not be run",
                    severity="info",
                    finding_class="informational",
                    confidence="confirmed",
                    identifier=f"{check.check_id}-unavailable",
                    location="host",
                    description=(
                        f"The query for '{check.title}' did not complete, so this setting "
                        f"has not been assessed on this host."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}"[:1000],
                    remediation_guidance="Verify WinRM connectivity and the account's read permissions.",
                ))
                continue

            output = (response.std_out or b"").decode("utf-8", errors="replace").strip()
            if response.status_code != 0:
                stderr = (response.std_err or b"").decode("utf-8", errors="replace").strip()
                context.findings.append(NormalizedFinding(
                    title=f"Check '{check.check_id}' returned an error",
                    severity="info",
                    finding_class="informational",
                    confidence="confirmed",
                    identifier=f"{check.check_id}-error",
                    location="host",
                    description=f"'{check.title}' could not be evaluated on this host.",
                    evidence=stderr[:1000] or f"exit code {response.status_code}",
                    remediation_guidance="Verify the account has permission to read this setting.",
                ))
                continue

            if output.lower() == check.failure_value.lower():
                context.findings.append(NormalizedFinding(
                    title=check.title,
                    severity=check.severity,
                    finding_class="misconfiguration",
                    # A credentialed query returns the live setting, so this is
                    # a direct observation rather than an inference.
                    confidence="confirmed",
                    identifier=check.check_id,
                    location="host",
                    description=check.description,
                    evidence=f"PowerShell: {check.query}\nReturned: {output}",
                    remediation_guidance=check.remediation,
                ))

    def get_status(self, session: ScanSession) -> ScanProgress:
        context: _AuditContext = session.context
        if not context.done.is_set():
            return ScanProgress(
                state=SessionState.RUNNING,
                percent_complete=None,
                message=context.progress_message,
            )
        if context.canceled.is_set():
            return ScanProgress(state=SessionState.CANCELED, message="Cancelled by an operator.")
        if context.error:
            return ScanProgress(state=SessionState.FAILED, error=context.error)
        return ScanProgress(state=SessionState.COMPLETED, percent_complete=100.0)

    def get_results(self, session: ScanSession) -> ScannerResult:
        progress = self.get_status(session)
        if not progress.finished:
            raise RuntimeError(f"Windows audit of {session.target} is still running.")

        context: _AuditContext = session.context
        if progress.state is not SessionState.COMPLETED:
            return ScannerResult(
                target=session.target,
                scanner_name=self.name,
                error=progress.error or "Audit did not complete.",
            )

        return ScannerResult(
            target=session.target,
            scanner_name=self.name,
            findings=[finding.as_dict() for finding in context.findings],
        )

    def cancel_scan(self, session: ScanSession) -> bool:
        context: _AuditContext = session.context
        if context.done.is_set():
            return False
        context.canceled.set()
        # The worker checks the flag between queries; a query already in flight
        # is left to finish rather than being abandoned mid-protocol.
        if context.thread is not None:
            context.thread.join(timeout=30)
        return True

    def normalize_results(self, raw: Any) -> list[NormalizedFinding]:
        return list(raw or [])
