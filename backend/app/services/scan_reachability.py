"""
Whether the machine running a scan can actually see the network it is aimed at.

This exists because of a failure mode that looks exactly like success. nmap
discovers hosts on a local segment with ARP: it asks "who has 192.168.1.7" on
the wire and listens for the reply. ARP is a layer-2 protocol, so it only works
when the scanner is *on* that segment. When it is not, nmap falls back to ICMP
and TCP ping probes, which are widely filtered, concludes that every address is
down, and exits 0 with an empty host list. The scan is reported complete. The
network appears empty. Nothing anywhere says the scanner was never on the right
side of a router.

Docker Desktop on Windows and macOS puts every container inside a Linux virtual
machine behind NAT, so the container's only interfaces are Docker bridges in
172.16/12. A worker there cannot ARP for anything on the laptop's Wi-Fi. It is
not a misconfiguration to be fixed in compose — `network_mode: host` is not
implemented on those platforms — it is a property of how Docker Desktop works.

So the platform checks first and says so. Per the no-fabrication rule, an empty
result from a scanner that could not reach the target is not evidence that the
target is empty, and must never be presented as though it were.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)

PROC_ROUTE = "/proc/net/route"
DOCKER_MARKER = "/.dockerenv"


@dataclass(frozen=True)
class Reachability:
    """What the scanning host can see, relative to one target."""

    target: str
    #: True when this host has an interface on the target's own segment, so
    #: ARP-based discovery will work.
    on_link: bool
    #: The directly-connected networks this host has, as strings.
    local_networks: tuple[str, ...] = ()
    #: How local_networks was determined, so an operator can tell an empty
    #: result from an unknown one.
    method: str = "unknown"
    containerized: bool = False
    summary: str = ""
    remediation: str | None = None

    @property
    def degraded(self) -> bool:
        """True when a scan will run but return materially less than expected."""
        return not self.on_link

    def as_log_lines(self) -> list[str]:
        """Lines to prepend to the operator-visible scan log."""
        if self.on_link:
            return []
        lines = [
            "[preflight] WARNING — this worker is not on the target network.",
            f"[preflight] Target: {self.target}",
            f"[preflight] This worker's directly-connected networks: "
            f"{', '.join(self.local_networks) or 'none detected'}",
            "[preflight] ARP host discovery cannot cross a router, so hosts that do "
            "not answer a TCP probe will be invisible, and none will report a MAC "
            "address or an OS fingerprint.",
            "[preflight] Falling back to a reduced scan: -Pn with service detection, "
            "no OS fingerprinting and no NSE vulnerability scripts. Those cannot "
            "produce reliable results across NAT, and running them against every "
            "address in the range would take hours on addresses that may not exist.",
            "[preflight] Treat a thin or empty result from this scan as "
            "inconclusive, not as an empty network.",
        ]
        if self.remediation:
            lines.append(f"[preflight] To fix: {self.remediation}")
        return lines


def _networks_from_proc_route() -> list[ipaddress.IPv4Network]:
    """
    Directly-connected IPv4 networks, read from the kernel routing table.

    /proc/net/route lists one route per line with Destination and Mask as
    little-endian hex. A route whose gateway is 0.0.0.0 and whose destination is
    non-zero is on-link — reachable without a router, which is exactly the
    condition ARP discovery needs.
    """
    networks: list[ipaddress.IPv4Network] = []
    try:
        with open(PROC_ROUTE, "r", encoding="utf-8") as handle:
            next(handle, None)  # header
            for line in handle:
                fields = line.split()
                if len(fields) < 8:
                    continue
                try:
                    # The kernel writes these as the hex of the 32-bit value in
                    # host byte order, which on every platform this runs on is
                    # little-endian. Parsing as an int and re-packing "<L"
                    # restores network byte order; going through bytes.fromhex
                    # instead silently yields the address reversed.
                    destination = int(fields[1], 16)
                    gateway = int(fields[2], 16)
                    mask = int(fields[7], 16)
                except ValueError:
                    continue
                if gateway != 0 or destination == 0 or mask == 0:
                    continue
                try:
                    network = ipaddress.IPv4Network(
                        (socket.inet_ntoa(struct.pack("<L", destination)),
                         socket.inet_ntoa(struct.pack("<L", mask))),
                        strict=False,
                    )
                except ValueError:
                    continue
                if network not in networks:
                    networks.append(network)
    except FileNotFoundError:
        return []
    except OSError:
        logger.exception("could not read %s", PROC_ROUTE)
        return []
    return networks


def _networks_from_scapy() -> list[ipaddress.IPv4Network]:
    """
    Fallback for hosts without /proc — a worker running natively on Windows.

    scapy is already a dependency for passive monitoring, so this costs no new
    package. Its route table is (network, netmask, gateway, iface, output_ip,
    metric) with the first three as integers or dotted strings depending on
    version, so both are handled.
    """
    try:
        from scapy.config import conf  # type: ignore
    except Exception:
        return []

    networks: list[ipaddress.IPv4Network] = []
    try:
        for entry in conf.route.routes:
            network_raw, mask_raw, gateway_raw = entry[0], entry[1], entry[2]

            def dotted(value) -> str:
                if isinstance(value, int):
                    return socket.inet_ntoa(struct.pack("!L", value))
                return str(value)

            gateway = dotted(gateway_raw)
            if gateway not in ("0.0.0.0", "::"):
                continue
            try:
                network = ipaddress.IPv4Network(
                    (dotted(network_raw), dotted(mask_raw)), strict=False
                )
            except ValueError:
                continue
            if network.prefixlen == 0 or network.is_loopback:
                continue
            if network not in networks:
                networks.append(network)
    except Exception:
        logger.exception("scapy route table could not be read")
        return []
    return networks


@lru_cache(maxsize=1)
def _local_networks_cached() -> tuple[tuple[str, ...], str]:
    networks = _networks_from_proc_route()
    method = "proc-route"
    if not networks:
        networks = _networks_from_scapy()
        method = "scapy" if networks else "unavailable"
    return tuple(str(n) for n in networks), method


def local_networks() -> tuple[tuple[str, ...], str]:
    """Directly-connected networks and how they were discovered."""
    return _local_networks_cached()


def reset_cache() -> None:
    """Interfaces change when a laptop moves between networks."""
    _local_networks_cached.cache_clear()


def _remediation(containerized: bool) -> str:
    if not containerized:
        return (
            "Run the scan worker on a machine with an interface on the target "
            "network, or add a route to it."
        )
    return (
        "The worker is in a container that is not attached to the target network. "
        "On a Linux Docker host, set 'network_mode: host' on the worker service in "
        "docker-compose.yml. On Docker Desktop for Windows or macOS host networking "
        "is not available at all — containers live in a NAT'd virtual machine — so "
        "run the Celery worker natively on the laptop instead: from backend/, "
        "'celery -A app.core.celery_app worker --loglevel=info' with DATABASE_URL and "
        "REDIS_URL pointed at the containers on localhost. nmap must be installed "
        "locally and the worker started with administrator rights for raw sockets."
    )


def assess_target(target: str) -> Reachability:
    """
    Decide whether a scan of `target` from this host can discover hosts properly.

    Never raises for a malformed target: target validation is the scanner's job
    and happens separately. An unparseable target simply reports unknown rather
    than blocking a scan on a preflight check.
    """
    containerized = os.path.exists(DOCKER_MARKER)
    names, method = local_networks()

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return Reachability(
            target=target, on_link=True, local_networks=names, method=method,
            containerized=containerized,
            summary="Target is not an IP network; no reachability claim is made.",
        )

    if not isinstance(network, ipaddress.IPv4Network):
        return Reachability(
            target=target, on_link=True, local_networks=names, method=method,
            containerized=containerized,
            summary="Only IPv4 reachability is assessed.",
        )

    if network.is_loopback:
        return Reachability(
            target=target, on_link=True, local_networks=names, method=method,
            containerized=containerized,
            summary="Target is loopback and is always reachable from this host.",
        )

    if method == "unavailable":
        # Do not claim a problem that was not observed. An unknown routing table
        # is not evidence of unreachability.
        return Reachability(
            target=target, on_link=True, local_networks=(), method=method,
            containerized=containerized,
            summary=(
                "This host's routing table could not be read, so reachability to "
                f"{network} is unknown. The scan will run as configured."
            ),
        )

    for name in names:
        local = ipaddress.IPv4Network(name)
        if local.overlaps(network):
            return Reachability(
                target=target, on_link=True, local_networks=names, method=method,
                containerized=containerized,
                summary=f"This host has an interface on {local}, which covers {network}.",
            )

    return Reachability(
        target=target,
        on_link=False,
        local_networks=names,
        method=method,
        containerized=containerized,
        summary=(
            f"This host has no interface on {network}. Its directly-connected "
            f"networks are {', '.join(names) or 'none'}. ARP host discovery cannot "
            f"cross a router, so hosts that do not answer a TCP probe will not be "
            f"found, and an empty result would not mean the network is empty."
        ),
        remediation=_remediation(containerized),
    )
