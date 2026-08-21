"""
Version comparison and CPE range membership.

An off-by-one at a range boundary either raises a vulnerability against a
patched host or hides one on an unpatched host. Both are worse than reporting
nothing, so the boundaries are pinned down explicitly.
"""
import pytest

from app.services.intel.versions import compare_versions, version_in_range


@pytest.mark.parametrize("left,right,expected", [
    ("1.0.0", "1.0.0", 0),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.1", -1),
    # The classic string-comparison trap: "1.2.10" sorts below "1.2.9" as text.
    ("1.2.10", "1.2.9", 1),
    ("1.10.0", "1.9.0", 1),
    ("2.0", "1.99.99", 1),
    # A longer version with a trailing numeric segment is greater.
    ("1.2.1", "1.2", 1),
    ("1.2", "1.2.0", -1),
    # Real-world shapes.
    ("8.9p1", "8.9p2", -1),
    ("8.9p1", "8.8p1", 1),
    ("1.24.0-1ubuntu1", "1.24.0", 1),
    ("2.4.57", "2.4.6", 1),
])
def test_ordering(left, right, expected):
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


@pytest.mark.parametrize("pre,release", [
    ("1.0rc1", "1.0"),
    ("2.0beta", "2.0"),
    ("3.0alpha", "3.0"),
    ("1.0.0-dev", "1.0.0"),
])
def test_pre_release_sorts_below_its_release(pre, release):
    assert compare_versions(pre, release) == -1


def test_numeric_segments_outrank_alphabetic_ones():
    assert compare_versions("1.2.3", "1.2.beta") == 1


# --- range membership ----------------------------------------------------

def test_inclusive_upper_bound_includes_the_boundary():
    assert version_in_range("1.2.3", end_including="1.2.3") is True
    assert version_in_range("1.2.4", end_including="1.2.3") is False


def test_exclusive_upper_bound_excludes_the_boundary():
    """'Fixed in 1.2.3' means 1.2.3 itself is safe."""
    assert version_in_range("1.2.3", end_excluding="1.2.3") is False
    assert version_in_range("1.2.2", end_excluding="1.2.3") is True


def test_inclusive_lower_bound_includes_the_boundary():
    assert version_in_range("1.0.0", start_including="1.0.0") is True
    assert version_in_range("0.9.9", start_including="1.0.0") is False


def test_exclusive_lower_bound_excludes_the_boundary():
    assert version_in_range("1.0.0", start_excluding="1.0.0") is False
    assert version_in_range("1.0.1", start_excluding="1.0.0") is True


def test_a_two_sided_range():
    assert version_in_range("1.5.0", start_including="1.0.0", end_excluding="2.0.0") is True
    assert version_in_range("2.0.0", start_including="1.0.0", end_excluding="2.0.0") is False
    assert version_in_range("0.9.0", start_including="1.0.0", end_excluding="2.0.0") is False


@pytest.mark.parametrize("version", ["", "*", "-", "any"])
def test_an_unknown_version_is_never_in_range(version):
    """Membership cannot be established without a version, so it is not claimed."""
    assert version_in_range(version, end_excluding="9.9.9") is False


def test_the_ten_versus_nine_trap_at_a_boundary():
    """openssh 8.9p1 must not be judged 'below 8.10' by string comparison."""
    assert version_in_range("8.9p1", end_excluding="8.10") is True
    assert version_in_range("8.10", end_excluding="8.10") is False
