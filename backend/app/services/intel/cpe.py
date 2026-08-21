"""
CPE 2.3 name parsing and matching.

A CPE name is the join key between "what is installed here" and "what is
vulnerable". Getting the matching rules right is the difference between a
vulnerability list an engineer trusts and one they stop reading.

Two rules are applied strictly:

* An asset component with no CPE is never matched. Falling back to fuzzy
  product-name matching would attach CVEs to the wrong software with full
  confidence, which is worse than reporting nothing.
* NVD's `vulnerable` flag is honoured. NVD uses non-vulnerable CPE nodes to
  express context ("this CVE affects product X *running on* platform Y"), and
  treating those as vulnerable would raise findings against the platform.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.intel.versions import WILDCARDS, version_in_range

ANY = "*"
NA = "-"


@dataclass(frozen=True)
class CpeName:
    """A parsed CPE 2.3 formatted string."""

    part: str = ANY
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    @property
    def is_application(self) -> bool:
        return self.part == "a"

    @property
    def is_operating_system(self) -> bool:
        return self.part == "o"

    def to_string(self) -> str:
        return ":".join([
            "cpe", "2.3", self.part, self.vendor, self.product, self.version,
            self.update, self.edition, self.language, self.sw_edition,
            self.target_sw, self.target_hw, self.other,
        ])


def _unescape(component: str) -> str:
    # CPE escapes separators and special characters with a backslash.
    result, index = [], 0
    while index < len(component):
        character = component[index]
        if character == "\\" and index + 1 < len(component):
            result.append(component[index + 1])
            index += 2
        else:
            result.append(character)
            index += 1
    return "".join(result)


def _split_components(value: str) -> list[str]:
    """Split on unescaped colons."""
    parts, current, index = [], [], 0
    while index < len(value):
        character = value[index]
        if character == "\\" and index + 1 < len(value):
            current.append(value[index:index + 2])
            index += 2
            continue
        if character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
        index += 1
    parts.append("".join(current))
    return parts


def parse_cpe(value: str) -> CpeName | None:
    """
    Parse a CPE 2.3 formatted string.

    Returns None for anything that is not a well-formed CPE 2.3 name. A partial
    or guessed parse would silently widen or narrow matching, so an
    unrecognisable value is rejected outright.
    """
    if not value:
        return None

    raw = value.strip()
    if not raw.lower().startswith("cpe:2.3:"):
        return None

    components = _split_components(raw)
    # cpe, 2.3, then 11 attribute components.
    if len(components) < 6:
        return None

    components = [_unescape(component).lower() for component in components[2:]]
    components += [ANY] * (11 - len(components))

    return CpeName(*components[:11])


def _component_matches(software_value: str, criteria_value: str) -> bool:
    """A criteria component matches if it is a wildcard or equal."""
    if criteria_value in (ANY, ""):
        return True
    if criteria_value == NA:
        return software_value in (NA, "")
    return software_value == criteria_value


def cpe_matches_software(
    criteria_cpe: str,
    software_cpe: str,
    *,
    software_version: str = "",
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
    vulnerable: bool = True,
) -> bool:
    """
    Whether an installed component matches a CVE's CPE rule.

    `software_version` is used when the installed component's CPE carries a
    wildcard version — common when the version came from a package inventory
    rather than being baked into the CPE string.
    """
    if not vulnerable:
        # A context-only node. Matching it would blame the platform for a flaw
        # in something running on it.
        return False

    criteria = parse_cpe(criteria_cpe)
    software = parse_cpe(software_cpe)
    if criteria is None or software is None:
        return False

    for attribute in ("part", "vendor", "product"):
        if not _component_matches(getattr(software, attribute), getattr(criteria, attribute)):
            return False

    for attribute in ("target_sw", "target_hw"):
        if not _component_matches(getattr(software, attribute), getattr(criteria, attribute)):
            return False

    effective_version = software.version
    if effective_version in WILDCARDS:
        effective_version = (software_version or "").strip()

    has_range = any([
        version_start_including, version_start_excluding,
        version_end_including, version_end_excluding,
    ])

    if has_range:
        if not effective_version or effective_version in WILDCARDS:
            # The rule is version-bounded but the installed version is unknown,
            # so membership cannot be established. Reporting a match here would
            # be a guess presented as a finding.
            return False
        return version_in_range(
            effective_version,
            start_including=version_start_including,
            start_excluding=version_start_excluding,
            end_including=version_end_including,
            end_excluding=version_end_excluding,
        )

    if criteria.version in (ANY, ""):
        # The rule covers every version of the product.
        return True

    if not effective_version or effective_version in WILDCARDS:
        return False

    return effective_version == criteria.version


def build_cpe(vendor: str, product: str, version: str = ANY, part: str = "a") -> str:
    """
    Build a CPE 2.3 string from known-good components.

    Used only where the values come from an authoritative source (a package
    manager, an inventory agent). It is deliberately *not* used to synthesise a
    CPE from a free-text service banner: a plausible-looking but wrong CPE
    produces confident, incorrect CVE matches.
    """
    def escape(value: str) -> str:
        return (value or ANY).strip().lower().replace(":", r"\:").replace(" ", "_")

    return CpeName(
        part=part, vendor=escape(vendor), product=escape(product), version=escape(version)
    ).to_string()
