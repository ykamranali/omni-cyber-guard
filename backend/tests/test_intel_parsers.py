"""
Feed parsers, exercised against payloads shaped exactly like the real feeds.

The fixtures below reproduce the structure of NVD 2.0 API responses, the CISA
KEV catalogue and the FIRST EPSS CSV, including the parts that are easy to get
wrong: nested configuration trees, multiple competing CVSS metrics, and the
comment header that carries EPSS's authoritative score date.
"""
from datetime import date, datetime, timezone

from app.services.intel.parsers import (
    parse_epss_csv, parse_kev_catalog, parse_nvd_cve, parse_nvd_page,
)

NVD_PAGE = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:38:51.163",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "es", "value": "Descripción en español"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "secondary@example.com",
                            "type": "Secondary",
                            "cvssData": {"baseScore": 9.0, "vectorString": "CVSS:3.1/AV:N/S:U", "baseSeverity": "CRITICAL"},
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseSeverity": "CRITICAL"},
                        },
                    ],
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 9.3}},
                    ],
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]},
                ],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "https://www.cisa.gov/uscert/ncas/current-activity"},
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "2.15.0",
                                    },
                                ],
                                "children": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
                                            },
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        },
        {
            "cve": {
                "id": "CVE-2026-00001",
                "published": "2026-08-01T00:00:00.000",
                "lastModified": "2026-08-01T00:00:00.000",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [{"lang": "en", "value": "Not yet analysed."}],
                "metrics": {},
                "configurations": [],
            },
        },
    ],
}


# --- NVD -----------------------------------------------------------------

def test_parses_a_page():
    records = parse_nvd_page(NVD_PAGE)
    assert [record.cve_id for record in records] == ["CVE-2021-44228", "CVE-2026-00001"]


def test_prefers_the_primary_cvss_source():
    """NVD's own analysis outranks a reporting party's score."""
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    assert record.cvss_v3_score == 10.0
    assert record.cvss_v3_severity == "CRITICAL"
    assert record.cvss_v2_score == 9.3


def test_prefers_the_english_description():
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    assert record.description.startswith("Apache Log4j2")


def test_only_real_cwe_identifiers_are_kept():
    """'NVD-CWE-noinfo' means no information, not a weakness class."""
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    assert record.cwe_ids == ["CWE-917"]


def test_timestamps_are_timezone_aware():
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    assert record.published_at == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc)
    assert record.last_modified_at.tzinfo is not None


def test_the_configuration_tree_is_walked_to_every_depth():
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    criteria = {match.criteria for match in record.cpe_matches}
    assert "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*" in criteria
    # The nested child node is found too...
    assert "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*" in criteria


def test_the_vulnerable_flag_is_preserved():
    """Losing it would turn 'runs on RHEL 8' into 'RHEL 8 is vulnerable'."""
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    by_criteria = {match.criteria: match for match in record.cpe_matches}
    assert by_criteria["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"].vulnerable is True
    assert by_criteria["cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*"].vulnerable is False


def test_version_bounds_are_preserved_exactly():
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][0])
    match = next(m for m in record.cpe_matches if "log4j" in m.criteria)
    assert match.version_start_including == "2.0"
    assert match.version_end_excluding == "2.15.0"
    assert match.version_end_including is None


def test_an_unscored_cve_gets_no_score_rather_than_a_default():
    record = parse_nvd_cve(NVD_PAGE["vulnerabilities"][1])
    assert record.cvss_v3_score is None
    assert record.cvss_v2_score is None
    assert record.vuln_status == "Awaiting Analysis"


def test_a_record_without_an_id_is_dropped():
    assert parse_nvd_cve({"cve": {"descriptions": []}}) is None


def test_an_empty_page_yields_nothing():
    assert parse_nvd_page({"vulnerabilities": []}) == []
    assert parse_nvd_page({}) == []


# --- CISA KEV ------------------------------------------------------------

KEV_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.20",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a vulnerability...",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://logging.apache.org/",
        },
        {
            "cveID": "cve-2023-4966",
            "vendorProject": "Citrix",
            "product": "NetScaler",
            "vulnerabilityName": "Citrix NetScaler Buffer Overflow",
            "dateAdded": "2023-10-18",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2023-11-08",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def test_kev_entries_are_parsed():
    entries = parse_kev_catalog(KEV_CATALOG)
    assert len(entries) == 2
    log4j = entries[0]
    assert log4j.cve_id == "CVE-2021-44228"
    assert log4j.date_added == date(2021, 12, 10)
    assert log4j.due_date == date(2021, 12, 24)
    assert log4j.known_ransomware_use is True


def test_kev_ids_are_normalised_to_upper_case():
    entries = parse_kev_catalog(KEV_CATALOG)
    assert entries[1].cve_id == "CVE-2023-4966"


def test_unknown_ransomware_use_is_not_treated_as_known():
    entries = parse_kev_catalog(KEV_CATALOG)
    assert entries[1].known_ransomware_use is False


def test_an_entry_without_a_cve_id_is_dropped():
    assert parse_kev_catalog({"vulnerabilities": [{"product": "Thing"}]}) == []


# --- FIRST EPSS ----------------------------------------------------------

EPSS_CSV = """#model_version:v2025.03.14,score_date:2026-08-21T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.975440000,0.999870000
CVE-2023-4966,0.941200000,0.999100000
CVE-2026-00001,0.000430000,0.070000000
"""


def test_epss_rows_are_parsed():
    scores, score_date = parse_epss_csv(EPSS_CSV)
    assert len(scores) == 3
    assert scores[0].cve_id == "CVE-2021-44228"
    assert scores[0].score == 0.97544
    assert scores[0].percentile == 0.99987


def test_the_score_date_comes_from_the_feed_not_from_today():
    """A stale file dated 'today' would silently misrepresent its freshness."""
    scores, score_date = parse_epss_csv(EPSS_CSV)
    assert score_date == date(2026, 8, 21)
    assert scores[0].scored_on == date(2026, 8, 21)


def test_a_malformed_row_is_skipped_without_discarding_the_file():
    content = EPSS_CSV + "CVE-BROKEN,not-a-number,also-bad\n"
    scores, _ = parse_epss_csv(content)
    assert len(scores) == 3


def test_an_empty_feed_parses_to_nothing():
    scores, score_date = parse_epss_csv("#model_version:v1,score_date:2026-08-21T00:00:00+0000\n")
    assert scores == []
    assert score_date == date(2026, 8, 21)
