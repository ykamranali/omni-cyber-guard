"""
Compatibility shim.

The scanner interface now lives in `app/scanners/contract.py`, which defines the
full lifecycle the platform needs (configuration probing, session start/status/
cancel, and normalization). This module re-exports the names the old two-method
interface used so existing imports keep working.

New adapters should import from `app.scanners.contract` directly.
"""
from app.scanners.contract import (  # noqa: F401
    ConfigurationStatus,
    NormalizedFinding,
    ScanProgress,
    ScanRequest,
    ScanSession,
    ScannerAdapter,
    ScannerAdapter as Scanner,
    ScannerCapability,
    ScannerResult,
    SessionState,
    TargetValidation,
)

__all__ = [
    "Scanner",
    "ScannerAdapter",
    "ScannerResult",
    "ScannerCapability",
    "ScanRequest",
    "ScanSession",
    "ScanProgress",
    "SessionState",
    "ConfigurationStatus",
    "TargetValidation",
    "NormalizedFinding",
]
