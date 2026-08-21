"""
CPE parsing and matching.

Matching decides which CVEs land on which hosts. A rule that is too loose fills
the queue with vulnerabilities the estate does not have; one that is too tight
hides real ones. Both boundaries are asserted here.
"""
import pytest

from app.services.intel.cpe import build_cpe, cpe_matches_software, parse_cpe

NGINX = "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
OPENSSH = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


# --- parsing -------------------------------------------------------------

def test_parses_a_well_formed_name():
    parsed = parse_cpe(NGINX)
    assert parsed is not None
    assert parsed.part == "a"
    assert parsed.vendor == "f5"
    assert parsed.product == "nginx"
    assert parsed.version == "1.24.0"
    assert parsed.is_application is True


def test_parsing_is_case_insensitive():
    assert parse_cpe("CPE:2.3:A:F5:NGINX:1.24.0:*:*:*:*:*:*:*").product == "nginx"


def test_escaped_separators_survive():
    parsed = parse_cpe(r"cpe:2.3:a:vendor:my\:product:1.0:*:*:*:*:*:*:*")
    assert parsed.product == "my:product"


@pytest.mark.parametrize("value", ["", "not-a-cpe", "cpe:/a:vendor:product", "cpe:2.3:a"])
def test_unparseable_values_are_rejected_rather_than_guessed(value):
    assert parse_cpe(value) is None


def test_missing_trailing_components_default_to_any():
    parsed = parse_cpe("cpe:2.3:a:vendor:product:1.0")
    assert parsed is not None
    assert parsed.language == "*"


# --- matching ------------------------------------------------------------

def test_exact_product_and_version_match():
    assert cpe_matches_software(NGINX, NGINX) is True


def test_a_different_product_does_not_match():
    apache = "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*"
    assert cpe_matches_software(NGINX, apache) is False


def test_a_different_vendor_does_not_match():
    """Two products can share a name; the vendor disambiguates them."""
    other = "cpe:2.3:a:someone_else:nginx:1.24.0:*:*:*:*:*:*:*"
    assert cpe_matches_software(NGINX, other) is False


def test_a_wildcard_version_rule_covers_every_version():
    rule = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_matches_software(rule, NGINX) is True


def test_version_range_matching():
    rule = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_matches_software(rule, NGINX, version_end_excluding="1.25.0") is True
    assert cpe_matches_software(rule, NGINX, version_end_excluding="1.24.0") is False
    assert cpe_matches_software(rule, NGINX, version_start_including="1.25.0") is False


def test_the_version_falls_back_to_the_inventory_value():
    """A CPE from a package inventory often carries a wildcard version."""
    software = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    rule = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_matches_software(
        rule, software, software_version="1.24.0", version_end_excluding="1.25.0"
    ) is True


def test_a_version_bounded_rule_never_matches_an_unknown_version():
    """A guess presented as a vulnerability finding is worse than reporting nothing."""
    software = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    rule = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_matches_software(rule, software, version_end_excluding="1.25.0") is False


def test_a_non_vulnerable_node_never_matches():
    """
    NVD marks some CPE nodes as context — 'affects X *running on* Y'. Treating
    those as vulnerable would blame the platform for a flaw in its tenant.
    """
    assert cpe_matches_software(NGINX, NGINX, vulnerable=False) is False


def test_target_software_must_agree_when_the_rule_specifies_it():
    rule = "cpe:2.3:a:vendor:plugin:1.0:*:*:*:*:wordpress:*:*"
    on_wordpress = "cpe:2.3:a:vendor:plugin:1.0:*:*:*:*:wordpress:*:*"
    on_drupal = "cpe:2.3:a:vendor:plugin:1.0:*:*:*:*:drupal:*:*"
    assert cpe_matches_software(rule, on_wordpress) is True
    assert cpe_matches_software(rule, on_drupal) is False


def test_an_operating_system_rule_does_not_match_an_application():
    os_rule = "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
    assert cpe_matches_software(os_rule, OPENSSH) is False


@pytest.mark.parametrize("bad", ["", "garbage", "cpe:/a:f5:nginx"])
def test_an_unparseable_side_never_matches(bad):
    assert cpe_matches_software(NGINX, bad) is False
    assert cpe_matches_software(bad, NGINX) is False


def test_build_cpe_round_trips():
    built = build_cpe("F5", "NGINX", "1.24.0")
    parsed = parse_cpe(built)
    assert parsed.vendor == "f5"
    assert parsed.product == "nginx"
    assert parsed.version == "1.24.0"
