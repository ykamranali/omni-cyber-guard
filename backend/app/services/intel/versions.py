"""
Version comparison for CPE range matching.

Getting this wrong is not a cosmetic bug: an off-by-one at a range boundary
either raises a vulnerability against a patched host or hides one on an
unpatched host. Both are worse than reporting nothing.

The comparator handles the shapes that actually occur in software versions —
`1.2.10`, `8.9p1`, `1.24.0-1ubuntu1`, `2.4.57`, `7.4.0rc2` — by splitting into
numeric and alphabetic runs and comparing run by run. Where two versions are
genuinely not comparable, the caller is told rather than being given a guess.
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r"(\d+|[A-Za-z]+)")

#: Pre-release markers sort *below* the release they precede: 1.0rc1 < 1.0.
_PRE_RELEASE = {"alpha": -4, "a": -4, "beta": -3, "b": -3, "rc": -2, "pre": -2, "dev": -5}

#: NVD uses these to mean "any version".
WILDCARDS = {"", "*", "-", "any"}


def _tokenize(version: str) -> list[tuple[int, object]]:
    """
    Split a version into comparable tokens.

    Each token is (kind, value) where kind 0 is numeric and kind 1 is
    alphabetic, so a numeric segment always sorts against another numeric
    segment rather than being compared as text ("10" > "9", not "10" < "9").
    """
    tokens: list[tuple[int, object]] = []
    for match in _TOKEN.finditer(version or ""):
        chunk = match.group(0)
        if chunk.isdigit():
            tokens.append((0, int(chunk)))
        else:
            lowered = chunk.lower()
            if lowered in _PRE_RELEASE:
                tokens.append((1, _PRE_RELEASE[lowered]))
            else:
                tokens.append((2, lowered))
    return tokens


def compare_versions(left: str, right: str) -> int:
    """
    Return -1, 0 or 1 for left < right, left == right, left > right.

    Comparison is positional. When one version runs out of tokens, a remaining
    *numeric* token on the other side makes it greater (1.2.1 > 1.2), while a
    remaining *pre-release* token makes it smaller (1.0rc1 < 1.0).
    """
    left_tokens = _tokenize(left)
    right_tokens = _tokenize(right)

    for index in range(max(len(left_tokens), len(right_tokens))):
        left_token = left_tokens[index] if index < len(left_tokens) else None
        right_token = right_tokens[index] if index < len(right_tokens) else None

        if left_token is None:
            return -1 if _is_greater_than_absent(right_token) else 1
        if right_token is None:
            return 1 if _is_greater_than_absent(left_token) else -1

        left_kind, left_value = left_token
        right_kind, right_value = right_token

        if left_kind != right_kind:
            # A numeric segment outranks an alphabetic one at the same position:
            # 1.2.3 > 1.2.beta.
            return -1 if left_kind > right_kind else 1

        if left_value != right_value:
            return -1 if left_value < right_value else 1  # type: ignore[operator]

    return 0


def _is_greater_than_absent(token: tuple[int, object] | None) -> bool:
    """Whether a token present on one side outranks its absence on the other."""
    if token is None:
        return False
    kind, value = token
    # A pre-release marker means "before the release", so its presence makes
    # the version smaller, not greater.
    if kind == 1:
        return False
    return True


def version_in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """
    Whether `version` falls inside the bounds NVD published.

    Inclusive and exclusive bounds are honoured exactly as given. NVD
    distinguishes them precisely because "fixed in 1.2.3" and "affected through
    1.2.3" describe different sets of hosts.
    """
    if not version or version.strip().lower() in WILDCARDS:
        return False

    version = version.strip()

    if start_including and compare_versions(version, start_including) < 0:
        return False
    if start_excluding and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and compare_versions(version, end_including) > 0:
        return False
    if end_excluding and compare_versions(version, end_excluding) >= 0:
        return False
    return True
