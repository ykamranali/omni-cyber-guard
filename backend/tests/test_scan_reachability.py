"""
Tests for the scan reachability preflight.

The behaviour under test is the one that made a broken scan look like a clean
one: a worker that cannot reach the target network completes, finds nothing,
and reports success. These assert that the condition is detected, that it is
explained in words an operator can act on, and — just as importantly — that it
is not claimed when it is not true.
"""
from __future__ import annotations

import pytest

from app.services import scan_reachability as sr


def _write_route(tmp_path, rows: list[tuple[str, str, str, str]]) -> str:
    """rows: (iface, destination_hex, gateway_hex, mask_hex), kernel byte order."""
    path = tmp_path / "route"
    lines = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"]
    for iface, dest, gw, mask in rows:
        lines.append(f"{iface}\t{dest}\t{gw}\t0001\t0\t0\t0\t{mask}\t0\t0\t0")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


# A Docker bridge: 172.18.0.0/16 on-link, plus a default route via 192.168.1.1.
DOCKER_BRIDGE = [
    ("eth0", "00000000", "0112A8C0", "00000000"),   # default route, ignored
    ("eth0", "000012AC", "00000000", "0000FFFF"),   # 172.18.0.0/16 on-link
]

# A worker sitting directly on the LAN: 192.168.1.0/24 on-link.
ON_LAN = [
    ("wlan0", "0001A8C0", "00000000", "00FFFFFF"),  # 192.168.1.0/24 on-link
]


@pytest.fixture(autouse=True)
def _clear_cache():
    sr.reset_cache()
    yield
    sr.reset_cache()


def test_reads_on_link_networks_in_the_right_byte_order(tmp_path, monkeypatch):
    # Parsing the hex the wrong way round yields a reversed address such as
    # 0.0.18.172 that silently never matches anything.
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    networks, method = sr.local_networks()
    assert networks == ("172.18.0.0/16",)
    assert method == "proc-route"


def test_default_route_is_not_treated_as_on_link(tmp_path, monkeypatch):
    # A default route reaches everything through a router — it must not be read
    # as evidence that every network is on the local segment.
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    assert "0.0.0.0/0" not in sr.local_networks()[0]


def test_lan_target_from_a_docker_bridge_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    result = sr.assess_target("192.168.1.0/24")

    assert result.on_link is False
    assert result.degraded is True
    assert "172.18.0.0/16" in result.local_networks
    assert result.remediation


def test_the_warning_says_an_empty_result_is_not_an_empty_network(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    text = " ".join(sr.assess_target("192.168.1.0/24").as_log_lines()).lower()

    assert "inconclusive" in text
    assert "not as an empty network" in text
    assert "-pn" in text


def test_worker_on_the_target_segment_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, ON_LAN))
    result = sr.assess_target("192.168.1.0/24")

    assert result.on_link is True
    assert result.degraded is False
    assert result.as_log_lines() == []


def test_single_host_on_the_segment_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, ON_LAN))
    assert sr.assess_target("192.168.1.42/32").on_link is True


def test_single_host_off_the_segment_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    assert sr.assess_target("192.168.1.42/32").on_link is False


def test_loopback_is_always_reachable(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    assert sr.assess_target("127.0.0.1/32").on_link is True


def test_unknown_routing_table_does_not_claim_a_problem(tmp_path, monkeypatch):
    # An unreadable routing table is missing evidence, not evidence of a fault.
    # Claiming degradation here would be a fabricated finding in its own right.
    monkeypatch.setattr(sr, "PROC_ROUTE", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(sr, "_networks_from_scapy", lambda: [])
    sr.reset_cache()

    result = sr.assess_target("192.168.1.0/24")
    assert result.method == "unavailable"
    assert result.on_link is True
    assert result.degraded is False
    assert "unknown" in result.summary.lower()


def test_malformed_target_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    result = sr.assess_target("not-a-network")
    assert result.on_link is True
    assert result.as_log_lines() == []


def test_container_remediation_names_the_docker_desktop_limitation(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "PROC_ROUTE", _write_route(tmp_path, DOCKER_BRIDGE))
    monkeypatch.setattr(sr.os.path, "exists", lambda p: p == sr.DOCKER_MARKER)

    remediation = sr.assess_target("192.168.1.0/24").remediation or ""
    assert "network_mode" in remediation
    assert "Docker Desktop" in remediation
    assert "celery" in remediation
