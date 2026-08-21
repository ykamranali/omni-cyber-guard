"""
Feed parsers.

Deliberately pure: each function takes a decoded payload and returns plain
records. No HTTP, no database, no clock. That is what makes them testable
against real captured responses, and it keeps the "what does this field mean"
decisions in one reviewable place.

Every parser follows the same rule — a field the feed does not supply comes back
empty or None. Nothing is defaulted to a value that would place a record
somewhere meaningful in a ranking it did not earn.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

@dataclass
class ParsedCpeMatch:
    criteria: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    vulnerable: bool = True


@dataclass
class ParsedCve:
    cve_id: str
    description: str = ""
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v3_severity: str | None = None
    cvss_v2_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    vuln_status: str = ""
    cpe_matches: list[ParsedCpeMatch] = field(default_factory=list)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for entry in descriptions or []:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _best_cvss_v3(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """
    Pick the most authoritative CVSS v3 score available.

    NVD publishes several: its own analysis (Primary) and the reporting party's
    (Secondary). The primary is preferred; v3.1 is preferred over v3.0.
    """
    candidates: list[tuple[int, float, str, str]] = []
    for key, version_rank in (("cvssMetricV31", 0), ("cvssMetricV30", 1)):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData", {}) or {}
            score = data.get("baseScore")
            if score is None:
                continue
            type_rank = 0 if entry.get("type") == "Primary" else 1
            candidates.append((
                version_rank * 2 + type_rank,
                float(score),
                data.get("vectorString", "") or "",
                (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper(),
            ))

    if not candidates:
        return None, None, None
    candidates.sort(key=lambda item: item[0])
    _, score, vector, severity = candidates[0]
    return score, vector or None, severity or None


def _best_cvss_v2(metrics: dict[str, Any]) -> float | None:
    for entry in metrics.get("cvssMetricV2", []) or []:
        score = (entry.get("cvssData", {}) or {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


def _walk_configuration_nodes(configurations: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield every cpeMatch in a CVE's configuration tree, at any depth."""
    for configuration in configurations or []:
        stack = list(configuration.get("nodes", []) or [])
        while stack:
            node = stack.pop()
            for match in node.get("cpeMatch", []) or []:
                yield match
            stack.extend(node.get("children", []) or [])


def parse_nvd_cve(item: dict[str, Any]) -> ParsedCve | None:
    """
    Parse one entry from an NVD 2.0 `vulnerabilities[]` array.

    Returns None for a record with no CVE ID, which cannot be stored or
    correlated against anything.
    """
    record = item.get("cve", item) or {}
    cve_id = (record.get("id") or "").strip().upper()
    if not cve_id:
        return None

    metrics = record.get("metrics", {}) or {}
    cvss_v3_score, cvss_v3_vector, cvss_v3_severity = _best_cvss_v3(metrics)

    cwe_ids: list[str] = []
    for weakness in record.get("weaknesses", []) or []:
        for description in weakness.get("description", []) or []:
            value = (description.get("value") or "").strip()
            if value.upper().startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)

    references = [
        reference.get("url", "")
        for reference in (record.get("references", []) or [])
        if reference.get("url")
    ]

    from app.services.intel.cpe import parse_cpe

    cpe_matches: list[ParsedCpeMatch] = []
    for match in _walk_configuration_nodes(record.get("configurations", []) or []):
        criteria = match.get("criteria") or ""
        if not criteria:
            continue
        parsed = parse_cpe(criteria)
        cpe_matches.append(ParsedCpeMatch(
            criteria=criteria,
            vendor=parsed.vendor if parsed else "",
            product=parsed.product if parsed else "",
            version=parsed.version if parsed else "",
            version_start_including=match.get("versionStartIncluding"),
            version_start_excluding=match.get("versionStartExcluding"),
            version_end_including=match.get("versionEndIncluding"),
            version_end_excluding=match.get("versionEndExcluding"),
            vulnerable=bool(match.get("vulnerable", True)),
        ))

    return ParsedCve(
        cve_id=cve_id,
        description=_english_description(record.get("descriptions", []) or []),
        published_at=_parse_timestamp(record.get("published")),
        last_modified_at=_parse_timestamp(record.get("lastModified")),
        cvss_v3_score=cvss_v3_score,
        cvss_v3_vector=cvss_v3_vector,
        cvss_v3_severity=cvss_v3_severity,
        cvss_v2_score=_best_cvss_v2(metrics),
        cwe_ids=cwe_ids,
        references=references[:50],
        vuln_status=record.get("vulnStatus", "") or "",
        cpe_matches=cpe_matches,
    )


def parse_nvd_page(payload: dict[str, Any]) -> list[ParsedCve]:
    """Parse a full NVD 2.0 API response page."""
    parsed = []
    for item in payload.get("vulnerabilities", []) or []:
        record = parse_nvd_cve(item)
        if record is not None:
            parsed.append(record)
    return parsed


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

@dataclass
class ParsedKevEntry:
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    short_description: str = ""
    required_action: str = ""
    date_added: date | None = None
    due_date: date | None = None
    known_ransomware_use: bool = False
    notes: str = ""


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_kev_catalog(payload: dict[str, Any]) -> list[ParsedKevEntry]:
    """Parse the CISA KEV JSON catalogue."""
    entries = []
    for item in payload.get("vulnerabilities", []) or []:
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entries.append(ParsedKevEntry(
            cve_id=cve_id,
            vendor_project=item.get("vendorProject", "") or "",
            product=item.get("product", "") or "",
            vulnerability_name=item.get("vulnerabilityName", "") or "",
            short_description=item.get("shortDescription", "") or "",
            required_action=item.get("requiredAction", "") or "",
            date_added=_parse_date(item.get("dateAdded")),
            due_date=_parse_date(item.get("dueDate")),
            # CISA writes "Known"/"Unknown"; anything else is treated as not known.
            known_ransomware_use=(item.get("knownRansomwareCampaignUse", "") or "").strip().lower() == "known",
            notes=item.get("notes", "") or "",
        ))
    return entries


# ---------------------------------------------------------------------------
# FIRST EPSS
# ---------------------------------------------------------------------------

@dataclass
class ParsedEpssScore:
    cve_id: str
    score: float
    percentile: float
    scored_on: date


def parse_epss_csv(content: str) -> tuple[list[ParsedEpssScore], date | None]:
    """
    Parse the EPSS daily CSV.

    The file starts with a comment line carrying the model version and the score
    date, e.g. `#model_version:v2025.03.14,score_date:2026-08-21T00:00:00+0000`.
    That date is the authoritative one — using "today" instead would silently
    misdate a stale file.
    """
    score_date: date | None = None
    data_lines: list[str] = []

    for line in content.splitlines():
        if line.startswith("#"):
            for token in line.lstrip("#").split(","):
                key, _, value = token.partition(":")
                if key.strip() == "score_date":
                    score_date = _parse_date(value.strip()[:10])
            continue
        if line.strip():
            data_lines.append(line)

    scores: list[ParsedEpssScore] = []
    if not data_lines:
        return scores, score_date

    reader = csv.DictReader(io.StringIO("\n".join(data_lines)))
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        try:
            score = float(row.get("epss", ""))
            percentile = float(row.get("percentile", ""))
        except (TypeError, ValueError):
            continue
        scores.append(ParsedEpssScore(
            cve_id=cve_id,
            score=score,
            percentile=percentile,
            scored_on=score_date or date.today(),
        ))

    return scores, score_date
