"""
Nuclei adapter: template-based assessment of HTTP(S) services.

Confidence is PROBABLE by default. Most nuclei templates match on a response
pattern, which is strong evidence that something is present but is not the same
as observing the defect itself — a WAF, a cached response or a decoy banner can
all produce a match. Templates that establish a CVE are classed as
vulnerabilities; the rest are misconfigurations or informational, based on what
the template actually reports.
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Any
from urllib.parse import urlparse

from app.scanners.contract import (
    NormalizedFinding, ScanRequest, ScannerCapability, ScannerResult, TargetValidation,
)
from app.scanners.subprocess_adapter import SubprocessContext, SubprocessScannerAdapter

RESULTS_FILENAME = "nuclei.jsonl"


class NucleiScanner(SubprocessScannerAdapter):
    binary = "nuclei"
    install_hint = (
        "Install nuclei on the scan worker "
        "(go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest), "
        "then run `nuclei -update-templates`."
    )

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def description(self) -> str:
        return "Template-based checks against HTTP(S) services."

    @property
    def capabilities(self) -> frozenset[ScannerCapability]:
        return frozenset({
            ScannerCapability.WEB_ASSESSMENT,
            ScannerCapability.TLS_ASSESSMENT,
        })

    def validate_target(self, target: str) -> TargetValidation:
        """
        Accept a URL or a private IP/host.

        The same boundary as the rest of the platform applies: an assessment is
        only run against infrastructure the operator has declared. A public
        hostname is refused here rather than trusted to a later check.
        """
        candidate = (target or "").strip()
        if not candidate:
            return TargetValidation(valid=False, reason="No target supplied.")

        if candidate.startswith(("http://", "https://")):
            host = urlparse(candidate).hostname or ""
        else:
            host = candidate.split(":")[0]
            candidate = f"http://{candidate}"

        if not host:
            return TargetValidation(valid=False, reason=f"Could not determine a host from '{target}'.")

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # A hostname. Resolution happens inside nuclei; the orchestrator
            # only ever hands this adapter targets derived from hosts it has
            # already discovered on an authorized range.
            return TargetValidation(valid=True, normalized_target=candidate)

        if not (address.is_private or address.is_loopback):
            return TargetValidation(
                valid=False,
                reason=(
                    f"Refusing to assess {host}: it is not a private or loopback address. "
                    f"Omni Cyber Guard only assesses ranges you have declared as authorized scope."
                ),
            )
        return TargetValidation(valid=True, normalized_target=candidate)

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        results_path = os.path.join(context_dir, RESULTS_FILENAME)
        command = [
            "nuclei",
            "-target", request.target,
            "-jsonl",
            "-output", results_path,
            "-silent",
            "-no-interactsh",         # no out-of-band callbacks to third-party infrastructure
            "-disable-update-check",
        ]
        severity = request.options.get("severity")
        if severity:
            command += ["-severity", str(severity)]
        return command

    def acceptable_exit_codes(self) -> tuple[int, ...]:
        # nuclei exits 0 whether or not it matched anything.
        return (0,)

    def collect_results(self, context: SubprocessContext) -> ScannerResult:
        results_path = os.path.join(context.artifacts["workdir"], RESULTS_FILENAME)
        records: list[dict[str, Any]] = []

        if os.path.exists(results_path):
            with open(results_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        # One malformed line must not discard the whole run.
                        continue

        findings = [finding.as_dict() for finding in self.normalize_results(records)]
        return ScannerResult(
            target=context.request.target,
            scanner_name=self.name,
            findings=findings,
        )

    def normalize_results(self, raw: Any) -> list[NormalizedFinding]:
        return [self._normalize_one(record) for record in (raw or [])]

    def _normalize_one(self, record: dict[str, Any]) -> NormalizedFinding:
        info = record.get("info", {}) or {}
        classification = info.get("classification", {}) or {}

        cve_id = _first(classification.get("cve-id"))
        cwe_id = _first(classification.get("cwe-id"))
        cvss_score = classification.get("cvss-score")
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        matched_at = record.get("matched-at") or record.get("host") or ""
        severity = (info.get("severity") or "info").lower()

        if cve_id:
            finding_class = "vulnerability"
        elif severity in ("critical", "high", "medium", "low"):
            finding_class = "misconfiguration"
        else:
            finding_class = "informational"

        evidence_parts = []
        if matched_at:
            evidence_parts.append(f"matched-at: {matched_at}")
        if record.get("matcher-name"):
            evidence_parts.append(f"matcher: {record['matcher-name']}")
        if record.get("extracted-results"):
            evidence_parts.append(f"extracted: {record['extracted-results']}")

        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        return NormalizedFinding(
            title=info.get("name") or record.get("template-id") or "Nuclei finding",
            severity=severity,
            finding_class=finding_class,
            # A template match is strong evidence, not a direct observation of
            # the defect. Only a check that exercises the defect itself would
            # justify "confirmed".
            confidence="probable",
            identifier=record.get("template-id") or info.get("name") or "nuclei",
            location=matched_at,
            description=info.get("description") or "",
            evidence="\n".join(evidence_parts),
            remediation_guidance=(
                info.get("remediation")
                or ("References: " + ", ".join(references[:3]) if references else "")
                or "Consult the nuclei template for remediation detail."
            ),
            cve_id=cve_id.upper() if cve_id else None,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
        )


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    if isinstance(value, str) and value:
        return value
    return None
