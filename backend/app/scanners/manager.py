"""
Registry of scanner adapters.

The registry is deliberately dumb: it holds adapters and reports what they say
about themselves. It never decides that a tool is available — only the adapter's
own `validate_configuration()` does that, by probing something real.
"""
from __future__ import annotations

import logging

from app.scanners.contract import ConfigurationStatus, ScannerAdapter, ScannerCapability

logger = logging.getLogger(__name__)


class ScannerManager:
    _scanners: dict[str, ScannerAdapter] = {}

    @classmethod
    def register_scanner(cls, scanner: ScannerAdapter) -> None:
        if scanner.name in cls._scanners:
            logger.warning("Scanner %s is already registered; overwriting.", scanner.name)
        cls._scanners[scanner.name] = scanner
        logger.info("Registered scanner adapter: %s (v%s)", scanner.name, scanner.version)

    @classmethod
    def get_scanner(cls, name: str) -> ScannerAdapter | None:
        return cls._scanners.get(name)

    @classmethod
    def get_all_scanners(cls) -> dict[str, ScannerAdapter]:
        return dict(cls._scanners)

    @classmethod
    def get_available_scanners(cls) -> dict[str, ScannerAdapter]:
        """Only adapters whose underlying tool is genuinely usable right now."""
        return {
            name: scanner
            for name, scanner in cls._scanners.items()
            if scanner.validate_configuration().available
        }

    @classmethod
    def scanners_with_capability(cls, capability: ScannerCapability) -> dict[str, ScannerAdapter]:
        return {
            name: scanner
            for name, scanner in cls._scanners.items()
            if capability in scanner.capabilities
        }

    @classmethod
    def configuration_report(cls) -> list[dict]:
        """
        Per-adapter status for the UI.

        This is what lets the Scan Center say "OpenVAS: integration not
        configured — set GVM_API_URL" instead of silently offering an engine
        that cannot run, or worse, appearing to run one that does nothing.
        """
        report = []
        for name, scanner in sorted(cls._scanners.items()):
            status: ConfigurationStatus = scanner.validate_configuration()
            report.append({
                "name": name,
                "adapter_version": scanner.version,
                "description": scanner.description,
                "capabilities": sorted(capability.value for capability in scanner.capabilities),
                "requires_credential": scanner.requires_credential,
                "available": status.available,
                "summary": status.summary,
                "remediation": status.remediation,
                "tool_version": status.tool_version,
            })
        return report

    @classmethod
    def reset(cls) -> None:
        """Test hook."""
        cls._scanners.clear()
