"""
Nmap adapter: host discovery, port and service enumeration, OS fingerprinting.

Safety boundary: `validate_target` refuses anything that is not a private or
loopback IPv4 range within the host-count cap, and it does so before
`start_scan` builds a command line — no packet is sent to an unauthorized
target, because no process is started for one.

The command is built as an argv list from validated components. No part of the
operator's input is ever passed through a shell.
"""
from __future__ import annotations

import os

from app.scanners.contract import (
    ConfigurationStatus, NormalizedFinding, ScanRequest, ScannerCapability,
    ScannerResult, TargetValidation,
)
from app.scanners.subprocess_adapter import SubprocessContext, SubprocessScannerAdapter
from app.services.scan_reachability import assess_target
from app.services.network_scanner import (
    RISKY_PORTS, ScanAuthorizationError, validate_authorized_target, _parse_nmap_xml,
)

XML_FILENAME = "scan.xml"


class NmapScanner(SubprocessScannerAdapter):
    binary = "nmap"
    install_hint = (
        "Install nmap on the scan worker (apt-get install nmap), or run the worker "
        "from the provided Docker image, which includes it."
    )

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def description(self) -> str:
        return "Host discovery, port and service enumeration, and OS fingerprinting."

    @property
    def capabilities(self) -> frozenset[ScannerCapability]:
        return frozenset({
            ScannerCapability.HOST_DISCOVERY,
            ScannerCapability.PORT_SCAN,
            ScannerCapability.SERVICE_DETECTION,
            ScannerCapability.OS_DETECTION,
        })

    def validate_configuration(self) -> ConfigurationStatus:
        status = super().validate_configuration()
        if not status.available:
            return status
        # OS detection and raw-socket scan types need elevated privileges.
        # Say so rather than letting the scan silently return less than expected.
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
            return ConfigurationStatus(
                available=True,
                summary=status.summary + " Running unprivileged.",
                remediation=(
                    "OS fingerprinting and SYN scanning need raw sockets. Grant the worker "
                    "CAP_NET_RAW (the provided docker-compose does this) or results will be "
                    "limited to TCP connect scanning."
                ),
                tool_version=status.tool_version,
            )
        return status

    def validate_target(self, target: str) -> TargetValidation:
        try:
            network = validate_authorized_target(target)
        except ScanAuthorizationError as exc:
            return TargetValidation(valid=False, reason=str(exc))
        return TargetValidation(valid=True, normalized_target=str(network))

    def preflight_notes(self, request: ScanRequest) -> list[str]:
        return assess_target(request.target).as_log_lines()

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        xml_path = os.path.join(context_dir, XML_FILENAME)

        if assess_target(request.target).degraded:
            # The worker is not on the target's segment, so ARP discovery is
            # impossible and every host would be reported down. -Pn skips
            # discovery and probes regardless, which is the only way to see
            # anything at all from behind NAT.
            #
            # -A and the vuln script set are dropped deliberately rather than
            # kept for appearances: OS fingerprinting needs raw packets whose
            # replies NAT does not preserve, and running NSE scripts against
            # every address in a /24 that is assumed up spends hours producing
            # nothing. Service detection is kept because banners do survive a
            # TCP connection.
            return [
                "nmap",
                "-Pn",
                "-sV",
                "-F",
                "-T4",
                "--max-retries", "1",
                "--host-timeout", "2m",
                "-v",
                "-oX", xml_path,
                request.target,
            ]

        return [
            "nmap",
            "-A",                       # OS detection, version detection, scripts, traceroute
            "--script", "vuln,default",
            "-F",                       # fast port set
            "-T4",
            "--max-retries", "1",
            "--host-timeout", "5m",
            "-v",                       # emit "Discovered ..." lines for the live log
            "-oX", xml_path,
            request.target,
        ]

    def is_progress_line(self, line: str) -> bool:
        return "Discovered" in line or "Scanning" in line or "Nmap scan report" in line

    def acceptable_exit_codes(self) -> tuple[int, ...]:
        # 1 means "some hosts were unreachable", which is a normal outcome.
        return (0, 1)

    def collect_results(self, context: SubprocessContext) -> ScannerResult:
        xml_path = os.path.join(context.artifacts["workdir"], XML_FILENAME)
        if not os.path.exists(xml_path):
            return ScannerResult(
                target=context.request.target,
                scanner_name=self.name,
                error=(
                    "nmap exited without writing its XML report, so no results were "
                    "produced. Output:\n" + context.output[-2000:]
                ),
            )

        with open(xml_path, "r", encoding="utf-8") as handle:
            hosts = _parse_nmap_xml(handle.read())

        return ScannerResult(
            target=context.request.target,
            scanner_name=self.name,
            findings=[],           # host data is normalized by the scan task
            raw_data=hosts,
            hosts_discovered=len(hosts),
        )

    def normalize_results(self, raw) -> list[NormalizedFinding]:
        """
        Turn parsed hosts into exposure findings.

        Only ports on the risky-service list produce a finding, and each one is
        classed as an EXPOSURE rather than a vulnerability: an open port is an
        observed fact about reachability, not evidence of a defect.
        """
        findings: list[NormalizedFinding] = []
        for host in raw or []:
            for port in host.ports:
                if port.port not in RISKY_PORTS:
                    continue
                label, guidance = RISKY_PORTS[port.port]
                location = f"{port.protocol}/{port.port}"
                banner = " ".join(part for part in (port.product, port.version) if part).strip()
                findings.append(NormalizedFinding(
                    title=f"Exposed {label} service on port {port.port}",
                    severity="high" if port.port in (23, 445, 3389, 5900) else "medium",
                    finding_class="exposure",
                    confidence="confirmed",
                    identifier=f"exposed-port-{port.port}",
                    location=location,
                    description=(
                        f"An open {label} port ({location}) was observed on {host.ip_address}. "
                        f"This is an exposure observation from service discovery — it is not a "
                        f"CVE-backed vulnerability."
                    ),
                    evidence=(
                        f"nmap: {location} open, service={port.service or 'unknown'}"
                        + (f", banner={banner}" if banner else "")
                    ),
                    remediation_guidance=guidance,
                    affected_product=port.product or None,
                    affected_version=port.version or None,
                ))
        return findings
