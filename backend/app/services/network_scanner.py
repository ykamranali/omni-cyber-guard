"""
Scan authorization and nmap result parsing.

Two responsibilities, both deliberately separate from process execution (which
belongs to `app/scanners/nmap.py`):

1. `validate_authorized_target` — the hard safety guardrail. Scans are only
   permitted against private (RFC1918) or loopback IPv4 ranges within a size
   cap. A request to scan a public range is rejected before any process is
   started, so no packet is ever sent to an unauthorized target.

2. `_parse_nmap_xml` — turns nmap's XML report into structured hosts, ports,
   services and script results. It extracts only what nmap reported; where a
   value is absent it stays absent rather than being inferred.

This module supports discovery and service fingerprinting only. No exploit
execution, no credential attacks, no payload delivery.
"""
from __future__ import annotations

import ipaddress
import platform
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable


class ScanAuthorizationError(Exception):
    """Raised when a scan target is not an authorized private range."""


class ScanCanceled(Exception):
    """Raised when an operator cancelled a scan and the scanner process was
    actually terminated as a result."""


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

MAX_SCAN_HOSTS = 1024  # caps target CIDR size (roughly a /22)
CANCEL_POLL_SECONDS = 3.0  # how often a running scan checks for a cancel request


@dataclass
class ScannedScript:
    id: str
    output: str


@dataclass
class ScannedPort:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    scripts: list[ScannedScript] = field(default_factory=list)


@dataclass
class ScannedHost:
    ip_address: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    os_match: str | None = None
    ports: list[ScannedPort] = field(default_factory=list)
    scripts: list[ScannedScript] = field(default_factory=list)


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


def get_arp_table() -> dict[str, str]:
    arp_map = {}
    try:
        import subprocess
        import re
        if platform.system() == "Windows":
            output = subprocess.check_output(["arp", "-a"], text=True)
            for line in output.splitlines():
                match = re.search(r"^\s*([0-9\.]+)\s+([0-9a-fA-F\-]+)\s+", line)
                if match:
                    arp_map[match.group(1)] = match.group(2).replace('-', ':').upper()
        else:
            output = subprocess.check_output(["arp", "-an"], text=True)
            for line in output.splitlines():
                match = re.search(r"\(([0-9\.]+)\) at ([0-9a-fA-F\:]+)", line)
                if match:
                    arp_map[match.group(1)] = match.group(2).upper()
    except Exception:
        pass
    return arp_map

def _parse_nmap_xml(xml_text: str) -> list[ScannedHost]:
    hosts: list[ScannedHost] = []
    root = ET.fromstring(xml_text)
    
    arp_table = get_arp_table()

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

        if not mac_address and ip_address in arp_table:
            mac_address = arp_table[ip_address]

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name")

        os_match = None
        os_el = host_el.find("os")
        if os_el is not None:
            import re
            best_raw_os = None
            # Iterate through all osmatch guesses and prefer major OSes over obscure hardware
            for osmatch_el in os_el.findall("osmatch"):
                raw_os = osmatch_el.get("name")
                if not raw_os:
                    continue
                if not best_raw_os:
                    best_raw_os = raw_os # Fallback to highest accuracy guess
                    
                # Clean up common Nmap OS strings for cleaner UI presentation
                if re.search(r"Windows 11", raw_os, re.IGNORECASE): os_match = "Windows 11"; break
                elif re.search(r"Windows 10", raw_os, re.IGNORECASE): os_match = "Windows 10"; break
                elif re.search(r"Windows Server 2022", raw_os, re.IGNORECASE): os_match = "Windows Server 2022"; break
                elif re.search(r"Windows Server 2019", raw_os, re.IGNORECASE): os_match = "Windows Server 2019"; break
                elif re.search(r"Windows Server 2016", raw_os, re.IGNORECASE): os_match = "Windows Server 2016"; break
                elif re.search(r"Windows Server", raw_os, re.IGNORECASE): os_match = "Windows Server"; break
                elif re.search(r"Windows 8", raw_os, re.IGNORECASE): os_match = "Windows 8"; break
                elif re.search(r"Windows 7", raw_os, re.IGNORECASE): os_match = "Windows 7"; break
                elif re.search(r"Windows XP", raw_os, re.IGNORECASE): os_match = "Windows XP"; break
                elif re.search(r"Windows", raw_os, re.IGNORECASE): os_match = "Windows (Unknown Version)"; break
                elif re.search(r"Linux 5\.", raw_os, re.IGNORECASE): os_match = "Linux 5.x"; break
                elif re.search(r"Linux 4\.", raw_os, re.IGNORECASE): os_match = "Linux 4.x"; break
                elif re.search(r"Linux 3\.", raw_os, re.IGNORECASE): os_match = "Linux 3.x"; break
                elif re.search(r"Linux 2\.6", raw_os, re.IGNORECASE): os_match = "Linux 2.6.x"; break
                elif re.search(r"Linux", raw_os, re.IGNORECASE): os_match = "Linux (Unknown Kernel)"; break
                elif re.search(r"macOS|Mac OS X|Apple", raw_os, re.IGNORECASE): os_match = "macOS"; break
                elif re.search(r"FreeBSD", raw_os, re.IGNORECASE): os_match = "FreeBSD"; break
                elif re.search(r"Cisco IOS", raw_os, re.IGNORECASE): os_match = "Cisco IOS"; break
            
            if not os_match and best_raw_os:
                os_match = best_raw_os.split("|")[0].strip()[:50]  # truncate long strings

        host_scripts: list[ScannedScript] = []
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                host_scripts.append(ScannedScript(id=script_el.get("id") or "unknown", output=script_el.get("output") or ""))

        ports: list[ScannedPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                
                # Fallback: if OS wasn't detected by fingerprint, check if a service leaked the OS
                if not os_match and service_el is not None:
                    ostype = service_el.get("ostype")
                    if ostype:
                        os_match = ostype

                port_scripts: list[ScannedScript] = []
                for script_el in port_el.findall("script"):
                    port_scripts.append(ScannedScript(id=script_el.get("id") or "unknown", output=script_el.get("output") or ""))
                    
                ports.append(ScannedPort(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol", "tcp"),
                    service=(service_el.get("name") if service_el is not None else "") or "unknown",
                    product=(service_el.get("product") if service_el is not None else "") or "",
                    version=(service_el.get("version") if service_el is not None else "") or "",
                    scripts=port_scripts
                ))

        hosts.append(ScannedHost(
            ip_address=ip_address, hostname=hostname, mac_address=mac_address, vendor=vendor, 
            os_match=os_match, ports=ports, scripts=host_scripts
        ))

    return hosts
