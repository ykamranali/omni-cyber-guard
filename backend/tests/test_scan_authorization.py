"""
The authorization guardrail is the single most important safety control in the
platform: it must reject public ranges before any packet leaves the host.
"""
import ipaddress

import pytest

from app.services.network_scanner import (
    MAX_SCAN_HOSTS,
    ScanAuthorizationError,
    validate_authorized_target,
)


@pytest.mark.parametrize("target", [
    "192.168.1.0/24",
    "10.0.0.0/24",
    "172.16.5.0/28",
    "127.0.0.1/32",
    "192.168.1.50",
])
def test_private_and_loopback_targets_are_allowed(target):
    assert isinstance(validate_authorized_target(target), ipaddress.IPv4Network)


@pytest.mark.parametrize("target", [
    "8.8.8.8/32",
    "1.1.1.0/24",
    "93.184.216.34",
    "0.0.0.0/0",
])
def test_public_targets_are_rejected(target):
    with pytest.raises(ScanAuthorizationError):
        validate_authorized_target(target)


@pytest.mark.parametrize("target", ["", "not-a-cidr", "192.168.1.0/99", "example.com"])
def test_malformed_targets_are_rejected(target):
    with pytest.raises(ScanAuthorizationError):
        validate_authorized_target(target)


def test_ipv6_is_rejected():
    with pytest.raises(ScanAuthorizationError):
        validate_authorized_target("fd00::/64")


def test_oversized_ranges_are_rejected():
    with pytest.raises(ScanAuthorizationError) as exc:
        validate_authorized_target("10.0.0.0/8")
    assert str(MAX_SCAN_HOSTS) in str(exc.value)


def test_boundary_range_is_allowed():
    network = validate_authorized_target("10.0.0.0/22")
    assert network.num_addresses == MAX_SCAN_HOSTS
