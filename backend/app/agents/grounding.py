"""
Grounding validation: does the answer only name records the database returned?

A language model asked about security will, if it has nothing to work with,
produce something that reads like security analysis. The failure is not
obviously a failure — invented CVE identifiers look exactly like real ones, and
an invented hostname looks exactly like a real one. On a platform whose central
rule is that no security result may be manufactured, an unchecked answer is a
fabrication channel.

So every answer is checked against the evidence set: the union of record
references returned by the retrieval tools during this request. Identifiers the
answer names that are not in that set were not obtained from the database, and
the answer is withheld.

What this catches
-----------------
Invented CVE identifiers, record UUIDs, hostnames and IP addresses — the
concrete referents an operator would act on.

What this does not catch, stated plainly
----------------------------------------
Wrong *quantities* and wrong *characterisations* of real records. "You have 40
critical findings" when the tool returned 12, or "this host is compromised"
about a host that merely has an open port, both pass this check. Two things
mitigate that rather than solve it: the tool results are attached verbatim to
every response so the operator can compare, and the system prompt forbids
asserting compromise. Neither is a substitute for reading the evidence, and the
UI is built to put it in front of the reader.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from app.models.agent import GroundingStatus

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Hostnames are only checked when they look like inventory hostnames: a label
# with an internal hyphen or digit, or a dotted name. Ordinary English words
# are not treated as claims about assets.
HOSTNAME_PATTERN = re.compile(
    r"\b(?=[a-z0-9-]*[-0-9])[a-z][a-z0-9-]{2,62}(?:\.[a-z][a-z0-9-]{1,62})*\b",
    re.IGNORECASE,
)

# Words that match the hostname shape but are vocabulary, not inventory.
_HOSTNAME_STOPWORDS = frozenset({
    "cve", "cvss", "epss", "kev", "cisa", "nvd", "sha-256", "sha-1", "md5",
    "tls-1", "ipv4", "ipv6", "utf-8", "http-only", "x-frame", "smbv1", "tcp-ip",
    "sql-injection", "cross-site", "man-in-the-middle", "e-mail", "read-only",
    "up-to-date", "well-known", "high-risk", "low-risk", "real-time", "so-called",
    "row-level", "multi-factor", "least-privilege", "defence-in-depth",
    "defense-in-depth", "end-of-life", "out-of-date", "third-party", "in-progress",
    "false-positive", "known-exploited", "internet-facing", "non-production",
    "24-hours", "30-days", "90-days", "p1", "p2", "p3", "p4",
})

INSUFFICIENT_EVIDENCE = (
    "I do not have sufficient evidence to answer that. Nothing in this "
    "organization's database matched what the question asked about. If you "
    "expected data here, the relevant scan or synchronisation may not have run."
)


class RejectionReason(str, Enum):
    UNSUPPORTED_REFERENCES = "unsupported_references"
    NO_EVIDENCE = "no_evidence"


@dataclass
class GroundingReport:
    status: GroundingStatus
    cited_refs: list[str] = field(default_factory=list)
    unsupported_refs: list[str] = field(default_factory=list)
    message: str = ""

    @property
    def accepted(self) -> bool:
        return self.status == GroundingStatus.GROUNDED

    def as_dict(self) -> dict:
        return {
            "status": self.status.value,
            "cited_references": list(self.cited_refs),
            "unsupported_references": list(self.unsupported_refs),
            "message": self.message,
            "validated": ["cve_id", "record_uuid", "ip_address", "hostname"],
            "not_validated": [
                "numeric totals",
                "characterisation of a record's meaning",
            ],
            "not_validated_note": (
                "Counts and interpretations are not machine-checked. The "
                "retrieved records are attached to this response so they can "
                "be compared directly."
            ),
        }


def extract_references(text: str) -> set[str]:
    """Concrete referents an answer names, normalised to evidence-set form."""
    if not text:
        return set()

    found: set[str] = set()
    # Hostname shape overlaps with UUIDs, CVE identifiers and dotted quads, so
    # those are matched first and blanked out before hostnames are scanned.
    # Otherwise a correctly-cited record UUID reads as an invented hostname and
    # a good answer gets withheld.
    remaining = list(text)

    def _blank(start: int, end: int) -> None:
        for index in range(start, end):
            remaining[index] = " "

    for match in CVE_PATTERN.finditer(text):
        found.add(f"cve:{match.group(0).upper()}")
        _blank(*match.span())
    for match in UUID_PATTERN.finditer(text):
        found.add(f"uuid:{match.group(0).lower()}")
        _blank(*match.span())
    for match in IPV4_PATTERN.finditer(text):
        octets = match.group(0).split(".")
        if all(octet.isdigit() and int(octet) <= 255 for octet in octets):
            found.add(f"ip:{match.group(0)}")
        _blank(*match.span())

    for match in HOSTNAME_PATTERN.finditer("".join(remaining)):
        candidate = match.group(0).lower().strip(".-")
        if candidate in _HOSTNAME_STOPWORDS:
            continue
        found.add(f"host:{candidate}")
    return found


def _normalise_evidence(evidence: set[str]) -> set[str]:
    """
    Widen the evidence set so a reference can be matched however it is written.

    A finding known as `finding:3f2a…` is also matched by the bare UUID, because
    an answer that quotes the identifier without its type prefix is still
    quoting a record it was shown. Hostnames are matched on their leftmost label
    too: retrieval returns `db-prod-01.corp.example.com`, and an answer naming
    `db-prod-01` is referring to the same host.
    """
    widened: set[str] = set()
    for ref in evidence:
        widened.add(ref)
        kind, _, value = ref.partition(":")
        if not value:
            continue
        if kind in ("finding", "asset", "scan_job", "remediation_task",
                    "compliance_framework", "compliance_assessment"):
            widened.add(f"uuid:{value.lower()}")
        if kind == "host":
            host = value.lower()
            widened.add(f"host:{host}")
            widened.add(f"host:{host.split('.')[0]}")
    return widened


def validate(answer: str, evidence: set[str], *, retrieved_any: bool) -> GroundingReport:
    """
    Decide whether `answer` may be shown to the operator.

    `retrieved_any` is whether any tool returned at least one row this request.
    An answer produced with no rows at all is refused outright, regardless of
    how careful it sounds — there was nothing to be careful about.
    """
    cited = extract_references(answer)

    if not retrieved_any:
        if not cited:
            # Nothing was retrieved and nothing specific was claimed. This is
            # the honest "no data" answer, and it is allowed through.
            return GroundingReport(
                status=GroundingStatus.NO_EVIDENCE,
                message=(
                    "No records were retrieved, so this response describes only "
                    "what is absent."
                ),
            )
        return GroundingReport(
            status=GroundingStatus.REJECTED,
            unsupported_refs=sorted(cited),
            message=(
                "The answer named specific records, but no database record was "
                "retrieved to support any of it. It has been withheld."
            ),
        )

    permitted = _normalise_evidence(evidence)
    unsupported = sorted(ref for ref in cited if ref not in permitted)

    if unsupported:
        return GroundingReport(
            status=GroundingStatus.REJECTED,
            cited_refs=sorted(cited & permitted),
            unsupported_refs=unsupported,
            message=(
                "The answer referred to identifiers that no database query "
                "returned, so it has been withheld rather than shown as "
                "analysis: " + ", ".join(unsupported)
            ),
        )

    return GroundingReport(
        status=GroundingStatus.GROUNDED,
        cited_refs=sorted(cited),
        message="Every identifier in this answer came from a database record.",
    )


def rejection_notice(report: GroundingReport) -> str:
    """What the operator sees in place of a withheld answer."""
    if report.status == GroundingStatus.NO_EVIDENCE:
        return INSUFFICIENT_EVIDENCE
    return (
        "I drafted an answer but withheld it: it referred to "
        + ", ".join(report.unsupported_refs)
        + ", which no query against your database returned. Rather than show "
        "you a security assessment containing identifiers I cannot trace to a "
        "record, I am reporting the failure. The retrieved records are attached "
        "below; ask again more specifically and I will work only from those."
    )
