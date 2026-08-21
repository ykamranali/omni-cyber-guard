"""
The scanner adapter contract.

These tests hold every adapter to the same obligations, including the ones
Phase 1 had to remove code for violating: an adapter must probe for its tool
rather than claiming availability, must refuse targets outside authorized
scope, and must never manufacture a finding.

The subprocess machinery is exercised against real commands (`sleep`, `sh`,
`printf`) so start / status / cancel / results are proven against actual
processes rather than mocks.
"""
from __future__ import annotations

import os
import time

import pytest

from app.scanners.contract import (
    ConfigurationStatus, ScanRequest, ScannerAdapter, ScannerCapability,
    ScannerResult, SessionState, TargetValidation,
)
from app.scanners.manager import ScannerManager
from app.scanners.subprocess_adapter import SubprocessContext, SubprocessScannerAdapter

ADAPTERS = list(ScannerManager.get_all_scanners().values())
ADAPTER_IDS = [adapter.name for adapter in ScannerManager.get_all_scanners().values()]


# --- obligations every adapter must meet ---------------------------------

@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_adapter_declares_its_identity(adapter: ScannerAdapter):
    assert adapter.name
    assert adapter.version
    assert adapter.capabilities, f"{adapter.name} declares no capabilities"
    assert all(isinstance(item, ScannerCapability) for item in adapter.capabilities)


@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_configuration_probe_returns_a_real_verdict(adapter: ScannerAdapter):
    """
    An adapter that hardcodes availability is the failure this contract exists
    to prevent. The verdict must be a genuine ConfigurationStatus, and when the
    tool is missing it must say what to install.
    """
    status = adapter.validate_configuration()
    assert isinstance(status, ConfigurationStatus)
    assert status.summary, f"{adapter.name} gave no explanation of its status"
    if not status.available:
        assert status.remediation, (
            f"{adapter.name} reports unavailable without telling the operator how to fix it"
        )


@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_empty_target_is_rejected(adapter: ScannerAdapter):
    assert adapter.validate_target("").valid is False


@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_rejection_always_carries_a_reason(adapter: ScannerAdapter):
    validation = adapter.validate_target("!!! not a target !!!")
    if not validation.valid:
        assert validation.reason


@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_normalizing_nothing_produces_nothing(adapter: ScannerAdapter):
    """The clearest statement of the no-fabrication rule: no input, no findings."""
    assert adapter.normalize_results([]) == []
    assert adapter.normalize_results(None) == []


@pytest.mark.parametrize("adapter", ADAPTERS, ids=ADAPTER_IDS)
def test_starting_a_scan_without_its_tool_raises_rather_than_pretending(adapter: ScannerAdapter):
    if adapter.validate_configuration().available:
        pytest.skip(f"{adapter.name}'s tool is installed in this environment")

    with pytest.raises((RuntimeError, ValueError)):
        adapter.start_scan(ScanRequest(target="192.168.1.0/24"))


# --- authorization boundary ----------------------------------------------

@pytest.mark.parametrize("target", ["8.8.8.8/32", "1.1.1.0/24", "93.184.216.34"])
def test_nmap_refuses_public_ranges(target):
    from app.scanners.nmap import NmapScanner

    validation = NmapScanner().validate_target(target)
    assert validation.valid is False
    assert "public" in validation.reason.lower() or "private" in validation.reason.lower()


def test_nmap_accepts_and_normalises_a_private_range():
    from app.scanners.nmap import NmapScanner

    validation = NmapScanner().validate_target("192.168.1.55/24")
    assert validation.valid is True
    assert validation.normalized_target == "192.168.1.0/24"


def test_nuclei_refuses_a_public_host():
    from app.scanners.nuclei import NucleiScanner

    validation = NucleiScanner().validate_target("http://93.184.216.34/")
    assert validation.valid is False


def test_nuclei_accepts_a_private_url():
    from app.scanners.nuclei import NucleiScanner

    validation = NucleiScanner().validate_target("192.168.1.10:8080")
    assert validation.valid is True
    assert validation.normalized_target == "http://192.168.1.10:8080"


def test_lynis_refuses_a_remote_target():
    """Lynis audits the machine it runs on; labelling that as a remote host would lie."""
    from app.scanners.lynis import LynisScanner

    validation = LynisScanner().validate_target("192.168.1.10")
    assert validation.valid is False
    assert "runs on" in validation.reason


def test_windows_audit_requires_a_credential():
    from app.scanners.windows_audit import WindowsAuditScanner

    adapter = WindowsAuditScanner()
    assert adapter.requires_credential is True

    if not adapter.validate_configuration().available:
        pytest.skip("pywinrm is not installed in this environment")

    with pytest.raises(ValueError, match="credential"):
        adapter.start_scan(ScanRequest(target="192.168.1.10"))


# --- credential redaction ------------------------------------------------

def test_a_scan_credential_never_prints_its_secret():
    from app.scanners.contract import ScanCredential

    credential = ScanCredential(
        credential_type="windows", username="svc", domain="CORP", secret="TopSecret123"
    )
    assert "TopSecret123" not in repr(credential)
    assert "TopSecret123" not in str(credential)
    assert "TopSecret123" not in f"{credential}"


# --- subprocess machinery, against real processes ------------------------

class _EchoAdapter(SubprocessScannerAdapter):
    """Minimal adapter over `printf`, used to exercise the base class."""

    binary = "printf"
    install_hint = "coreutils"

    @property
    def name(self) -> str:
        return "echo-test"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self):
        return frozenset({ScannerCapability.PORT_SCAN})

    def validate_target(self, target: str) -> TargetValidation:
        if not target:
            return TargetValidation(valid=False, reason="No target supplied.")
        return TargetValidation(valid=True, normalized_target=target)

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        return ["printf", "line one\nline two\n"]

    def collect_results(self, context: SubprocessContext) -> ScannerResult:
        return ScannerResult(
            target=context.request.target,
            scanner_name=self.name,
            findings=[],
            raw_data=context.output_lines,
        )

    def normalize_results(self, raw):
        return []


class _SlowAdapter(_EchoAdapter):
    @property
    def name(self) -> str:
        return "slow-test"

    binary = "sleep"

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        return ["sleep", "30"]


class _FailingAdapter(_EchoAdapter):
    @property
    def name(self) -> str:
        return "failing-test"

    binary = "sh"

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        return ["sh", "-c", "echo 'something broke' >&2; exit 3"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_a_session_runs_to_completion_and_captures_output():
    adapter = _EchoAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1"))

    deadline = time.monotonic() + 15
    while not adapter.get_status(session).finished and time.monotonic() < deadline:
        time.sleep(0.05)

    progress = adapter.get_status(session)
    assert progress.state is SessionState.COMPLETED
    assert progress.percent_complete == 100.0

    result = adapter.get_results(session)
    assert result.raw_data == ["line one", "line two"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_results_are_refused_while_a_scan_is_still_running():
    """Partial results returned as complete would misrepresent coverage."""
    adapter = _SlowAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1", timeout_seconds=60))
    try:
        assert adapter.get_status(session).state is SessionState.RUNNING
        with pytest.raises(RuntimeError, match="still running"):
            adapter.get_results(session)
    finally:
        adapter.cancel_scan(session)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_cancelling_terminates_the_real_process():
    adapter = _SlowAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1", timeout_seconds=60))
    process = session.context.process

    assert process.poll() is None
    assert adapter.cancel_scan(session) is True
    assert process.poll() is not None, "the process was reported cancelled but is still alive"
    assert adapter.get_status(session).state is SessionState.CANCELED


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_cancelling_a_finished_scan_reports_that_nothing_was_stopped():
    adapter = _EchoAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1"))
    session.context.process.wait(timeout=15)
    assert adapter.cancel_scan(session) is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_a_nonzero_exit_is_a_failure_carrying_the_tool_output():
    adapter = _FailingAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1"))

    deadline = time.monotonic() + 15
    while not adapter.get_status(session).finished and time.monotonic() < deadline:
        time.sleep(0.05)

    progress = adapter.get_status(session)
    assert progress.state is SessionState.FAILED
    assert "exited with code 3" in progress.error
    assert "something broke" in progress.error

    result = adapter.get_results(session)
    assert result.error
    assert result.findings == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_a_scan_that_exceeds_its_budget_is_terminated():
    adapter = _SlowAdapter()
    session = adapter.start_scan(ScanRequest(target="10.0.0.1", timeout_seconds=1))
    time.sleep(1.2)

    progress = adapter.get_status(session)
    assert progress.state is SessionState.FAILED
    assert "budget" in progress.error
    assert session.context.process.poll() is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell tools required")
def test_run_to_completion_honours_a_cancel_request():
    adapter = _SlowAdapter()
    result = adapter.run_to_completion(
        ScanRequest(target="10.0.0.1", timeout_seconds=60),
        cancel_check=lambda: True,
        poll_interval=0.05,
    )
    assert result.error


def test_a_missing_binary_is_reported_with_remediation():
    class _MissingAdapter(_EchoAdapter):
        binary = "definitely-not-a-real-binary-xyz"
        install_hint = "Install the thing."

        @property
        def name(self) -> str:
            return "missing-test"

    status = _MissingAdapter().validate_configuration()
    assert status.available is False
    assert "definitely-not-a-real-binary-xyz" in status.summary
    assert status.remediation == "Install the thing."


# --- registry ------------------------------------------------------------

def test_the_registry_reports_availability_per_adapter():
    report = ScannerManager.configuration_report()
    assert report
    for entry in report:
        assert set(entry) >= {
            "name", "available", "summary", "remediation", "capabilities", "requires_credential",
        }
        if not entry["available"]:
            assert entry["remediation"]


def test_available_scanners_is_a_subset_of_all_scanners():
    assert set(ScannerManager.get_available_scanners()) <= set(ScannerManager.get_all_scanners())


def test_capability_lookup_finds_the_right_adapters():
    discovery = ScannerManager.scanners_with_capability(ScannerCapability.HOST_DISCOVERY)
    assert "nmap" in discovery

    credentialed = ScannerManager.scanners_with_capability(ScannerCapability.CREDENTIALED)
    assert "windows_audit" in credentialed
    assert "nmap" not in credentialed
