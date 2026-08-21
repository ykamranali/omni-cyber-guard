"""
Scanner registry for Omni Cyber Guard.

Every adapter registered here wraps a real external tool and reports its own
availability by probing for that tool. An adapter whose binary, service or
library is absent reports `available=False` with concrete remediation — it never
fabricates results.

The `openvas` and `zap` engines were removed in the Phase 1 cleanup. Neither
contained an integration: both emitted hardcoded findings, including claims of
successful SQL injection, which were persisted as if a real assessment had
produced them. Genuine GVM/GMP and ZAP-daemon adapters belong here when they are
written; until then those engines do not exist rather than pretending to work.
"""
from app.scanners.contract import (
    ConfigurationStatus,
    NormalizedFinding,
    ScanProgress,
    ScanRequest,
    ScanSession,
    ScannerAdapter,
    ScannerCapability,
    ScannerResult,
    SessionState,
    TargetValidation,
)
from app.scanners.manager import ScannerManager
from app.scanners.subprocess_adapter import SubprocessScannerAdapter

from app.scanners.lynis import LynisScanner
from app.scanners.nmap import NmapScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.windows_audit import WindowsAuditScanner

ScannerManager.register_scanner(NmapScanner())
ScannerManager.register_scanner(NucleiScanner())
ScannerManager.register_scanner(LynisScanner())
ScannerManager.register_scanner(WindowsAuditScanner())

__all__ = [
    "ScannerAdapter",
    "ScannerManager",
    "ScannerResult",
    "ScannerCapability",
    "ScanRequest",
    "ScanSession",
    "ScanProgress",
    "SessionState",
    "ConfigurationStatus",
    "TargetValidation",
    "NormalizedFinding",
    "SubprocessScannerAdapter",
]
