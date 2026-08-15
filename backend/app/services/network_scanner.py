"""
Real network discovery + port/service scanning, backed by the `nmap`
binary. This module intentionally supports discovery and service
fingerprinting only — no exploit execution, no credential attacks, no
payload delivery. It is designed exclusively for authorized scanning of
networks the operator owns or is explicitly authorized to assess.

Hard safety guardrail: scans are only permitted against private (RFC1918)
or loopback address ranges. Any request to scan a public IP range is
rejected before a single packet is sent.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


class ScanAuthorizationError(Exception):
    """Raised when a scan target is not an authorized private range."""


# Ports considered inherently risky to expose, with a short, generic,
# non-CVE-specific rationale. This is a hygiene heuristic, not a
# vulnerability database — it never fabricates CVE IDs or CVSS scores.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "Unencrypted file transfer protocol. Prefer SFTP/FTPS, or restrict access to trusted hosts only."),
    23: ("Telnet", "Unencrypted remote administration protocol. Replace with SSH and disable Telnet."),
    25: ("SMTP", "Open mail relay risk if misconfigured. Verify relay restrictions and authentication are enforced."),
    135: ("MSRPC", "Windows RPC endpoint mapper. Restrict exposure to trusted network segments only."),
    139: ("NetBIOS", "Legacy Windows file-sharing protocol with a history of remote exploitation. Disable if unused."),
    445: ("SMB", "Windows file-sharing protocol frequently targeted by lateral-movement malware. Patch and restrict to trusted segments."),
    1433: ("MSSQL", "Database service exposed directly to the network. Restrict to application servers only, never expose publicly."),
    3306: ("MySQL", "Database service exposed directly to the network. Restrict to application servers only."),
    3389: ("RDP", "Remote Desktop Protocol is a top ransomware entry vector when internet-exposed. Restrict to VPN access and enforce MFA."),
    5432: ("PostgreSQL", "Database service exposed directly to the network. Restrict to application servers only."),
    5900: ("VNC", "Remote desktop protocol often deployed with weak or no authentication. Restrict access and require strong auth."),
    6379: ("Redis", "In-memory data store historically deployed with no authentication. Enable AUTH and bind to internal interfaces only."),
    27017: ("MongoDB", "Database service frequently found exposed with no authentication in the wild. Restrict to application servers only."),
}

MAX_SCAN_HOSTS = 1024  # caps target CIDR size (roughly a /22) to keep scans fast and bounded


@dataclass
class ScannedPort:
    port: int
    protocol: str
    service: str
    product: str
    version: str


@dataclass
class ScannedHost:
    ip_address: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    ports: list[ScannedPort] = field(default_factory=list)


def validate_authorized_target(target_cidr: str) -> ipaddress.IPv4Network:
    """
    Raises ScanAuthorizationError unless target_cidr is a private or
    loopback IPv4 network within the configured host-count cap.
    """
    try:
        network = ipaddress.ip_network(target_cidr, strict=False)
    except ValueError as exc:
        raise ScanAuthorizationError(f"'{target_cidr}' is not a valid CIDR range.") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise ScanAuthorizationError("Only IPv4 targets are supported.")

    if not (network.is_private or network.is_loopback):
        raise ScanAuthorizationError(
            "Refusing to scan a public IP range. Omni Cyber Guard only scans private "
            "(RFC1918) or loopback address ranges that you are authorized to assess."
        )

    if network.num_addresses > MAX_SCAN_HOSTS:
        raise ScanAuthorizationError(
            f"Target range is too large ({network.num_addresses} addresses). "
            f"Scan at most a /22 ({MAX_SCAN_HOSTS} addresses) at a time."
        )

    return network


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_discovery_and_service_scan(target_cidr: str, timeout_seconds: int = 600) -> list[ScannedHost]:
    """
    Runs `nmap -sV -O --osscan-guess` (service/version + best-effort OS
    guess) against an authorized private CIDR range and parses the XML
    output. Requires the `nmap` binary to be installed in the runtime
    environment (see backend/Dockerfile).
    """
    network = validate_authorized_target(target_cidr)

    if not nmap_available():
        raise RuntimeError(
            "The 'nmap' binary is not installed in this environment. "
            "Install it (e.g. `apt-get install nmap`) or use the provided Docker image."
        )

    cmd = ["nmap", "-sV", "--osscan-guess", "-O", "-T4", "-oX", "-", str(network)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Scan of {target_cidr} timed out after {timeout_seconds}s.") from exc

    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        # nmap can return non-zero with partial XML on some permission errors (e.g. no raw socket
        # capability); surface stderr so the operator can fix the environment.
        raise RuntimeError(f"nmap scan failed (exit {proc.returncode}): {proc.stderr.strip()[:2000]}")

    return _parse_nmap_xml(proc.stdout)


def _parse_nmap_xml(xml_text: str) -> list[ScannedHost]:
    hosts: list[ScannedHost] = []
    root = ET.fromstring(xml_text)

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ip_address = None
        mac_address = None
        vendor = None
        for addr_el in host_el.findall("address"):
            addr_type = addr_el.get("addrtype")
            if addr_type == "ipv4":
                ip_address = addr_el.get("addr")
            elif addr_type == "mac":
                mac_address = addr_el.get("addr")
                vendor = addr_el.get("vendor") or None

        if not ip_address:
            continue

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name")

        ports: list[ScannedPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                ports.append(ScannedPort(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol", "tcp"),
                    service=(service_el.get("name") if service_el is not None else "") or "unknown",
                    product=(service_el.get("product") if service_el is not None else "") or "",
                    version=(service_el.get("version") if service_el is not None else "") or "",
                ))

        hosts.append(ScannedHost(
            ip_address=ip_address, hostname=hostname, mac_address=mac_address, vendor=vendor, ports=ports,
        ))

    return hosts
