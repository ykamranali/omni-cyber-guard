"""
Lynis adapter: host hardening audit.

Scope note, stated plainly because the previous implementation blurred it:
Lynis audits the machine it runs on. This adapter therefore assesses the scan
worker itself, and `validate_target` accepts only the local host. Auditing a
remote host requires either an SSH transport or an agent, neither of which
exists yet — so the adapter refuses a remote target rather than running locally
and labelling the results with someone else's hostname.
"""
from __future__ import annotations

import os
from typing import Any

from app.scanners.contract import (
    NormalizedFinding, ScanRequest, ScannerCapability, ScannerResult, TargetValidation,
)
from app.scanners.subprocess_adapter import SubprocessContext, SubprocessScannerAdapter

REPORT_FILENAME = "lynis-report.dat"
LOCAL_TARGETS = {"localhost", "127.0.0.1", "local", "self", "::1"}


class LynisScanner(SubprocessScannerAdapter):
    binary = "lynis"
    install_hint = (
        "Install lynis on the scan worker (apt-get install lynis). Note that Lynis "
        "audits the host it runs on, so this assesses the worker itself."
    )

    @property
    def name(self) -> str:
        return "lynis"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def description(self) -> str:
        return "Configuration hardening audit of the local host."

    @property
    def capabilities(self) -> frozenset[ScannerCapability]:
        return frozenset({ScannerCapability.CONFIGURATION_AUDIT})

    def validate_target(self, target: str) -> TargetValidation:
        candidate = (target or "").strip().lower()
        if not candidate:
            # Silently defaulting an empty target to "localhost" would audit the
            # worker while the operator believed they had scanned something else.
            return TargetValidation(
                valid=False,
                reason="No target supplied. Use 'localhost' to audit the scan worker itself.",
            )
        if candidate in LOCAL_TARGETS:
            return TargetValidation(valid=True, normalized_target="localhost")
        return TargetValidation(
            valid=False,
            reason=(
                f"Lynis audits the host it runs on, so it cannot assess '{target}'. "
                f"Target 'localhost' to audit the scan worker. Remote hardening audits "
                f"require an SSH transport or an agent, which is not implemented yet."
            ),
        )

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        return [
            "lynis", "audit", "system",
            "--quick",
            "--no-colors",
            "--report-file", os.path.join(context_dir, REPORT_FILENAME),
        ]

    def acceptable_exit_codes(self) -> tuple[int, ...]:
        # Lynis uses non-zero codes to signal warnings, which are results, not failures.
        return (0, 1, 2, 78)

    def is_progress_line(self, line: str) -> bool:
        return line.startswith("[") or "Performing" in line

    def collect_results(self, context: SubprocessContext) -> ScannerResult:
        report_path = os.path.join(context.artifacts["workdir"], REPORT_FILENAME)
        if not os.path.exists(report_path):
            return ScannerResult(
                target=context.request.target,
                scanner_name=self.name,
                error=(
                    "lynis finished without writing a report file, so nothing was assessed. "
                    "Output:\n" + context.output[-2000:]
                ),
            )

        with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
            records = self._parse_report(handle.read())

        return ScannerResult(
            target=context.request.target,
            scanner_name=self.name,
            findings=[finding.as_dict() for finding in self.normalize_results(records)],
        )

    def _parse_report(self, content: str) -> list[dict[str, Any]]:
        """Extract warnings and suggestions from the .dat report."""
        records: list[dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if not (line.startswith("warning[]") or line.startswith("suggestion[]")):
                continue
            kind, _, payload = line.partition("=")
            parts = payload.split("|")
            if len(parts) < 2:
                continue
            records.append({
                "kind": "warning" if kind.startswith("warning") else "suggestion",
                "test_id": parts[0],
                "message": parts[1],
                "details": parts[2] if len(parts) > 2 else "",
                "raw": line,
            })
        return records

    def normalize_results(self, raw: Any) -> list[NormalizedFinding]:
        findings = []
        for record in raw or []:
            is_warning = record["kind"] == "warning"
            findings.append(NormalizedFinding(
                title=f"Lynis {record['test_id']}: {record['message']}",
                severity="high" if is_warning else "low",
                finding_class="misconfiguration",
                # Lynis reads the live configuration, so the observation is direct.
                confidence="confirmed",
                identifier=record["test_id"],
                location="host",
                description=record["message"],
                evidence=record["raw"],
                remediation_guidance=(
                    f"Review the Lynis documentation for test {record['test_id']} "
                    f"and apply the recommended hardening."
                ),
            ))
        return findings
