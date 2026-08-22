"""
Grounding validation: an answer may only name records the database returned.

These tests exist because the failure they guard against is invisible. An
invented CVE identifier is shaped exactly like a real one; an invented hostname
reads exactly like an asset. On a platform whose central rule is that no
security result may be manufactured, the check that distinguishes the two is
load-bearing, and so is its honesty about what it does not check.
"""
from __future__ import annotations

from app.agents import grounding
from app.models.agent import GroundingStatus


class TestReferenceExtraction:
    def test_cve_identifiers_are_extracted(self):
        refs = grounding.extract_references("This host is affected by CVE-2024-3094.")
        assert "cve:CVE-2024-3094" in refs

    def test_cve_extraction_is_case_insensitive_and_normalised(self):
        refs = grounding.extract_references("see cve-2021-44228")
        assert "cve:CVE-2021-44228" in refs

    def test_record_uuids_are_extracted(self):
        text = "Finding 3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071 is still open."
        refs = grounding.extract_references(text)
        assert "uuid:3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071" in refs

    def test_ipv4_addresses_are_extracted(self):
        refs = grounding.extract_references("Port 22 is open on 192.168.10.14.")
        assert "ip:192.168.10.14" in refs

    def test_impossible_dotted_quads_are_not_treated_as_addresses(self):
        """Version strings like 999.1.1.1 are not addresses and must not be
        checked as though they were."""
        refs = grounding.extract_references("build 999.300.1.1")
        assert not any(ref.startswith("ip:") for ref in refs)

    def test_inventory_shaped_hostnames_are_extracted(self):
        refs = grounding.extract_references("db-prod-01 is the busiest host.")
        assert "host:db-prod-01" in refs

    def test_ordinary_words_are_not_treated_as_hostnames(self):
        text = "The service should be restarted after patching the package."
        refs = grounding.extract_references(text)
        assert not any(ref.startswith("host:") for ref in refs)

    def test_security_vocabulary_is_not_treated_as_a_hostname(self):
        text = "The CVSS and EPSS values disagree; SMBv1 is enabled."
        refs = grounding.extract_references(text)
        assert not any(ref.startswith("host:") for ref in refs)


class TestValidation:
    def test_an_answer_citing_only_retrieved_records_is_accepted(self):
        report = grounding.validate(
            "CVE-2024-3094 affects db-prod-01.",
            {"cve:CVE-2024-3094", "host:db-prod-01"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.GROUNDED
        assert report.accepted

    def test_an_invented_cve_is_rejected(self):
        report = grounding.validate(
            "You are also exposed to CVE-2019-0708.",
            {"cve:CVE-2024-3094"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.REJECTED
        assert report.unsupported_refs == ["cve:CVE-2019-0708"]

    def test_an_invented_host_is_rejected(self):
        report = grounding.validate(
            "The issue is on mail-relay-07.",
            {"host:db-prod-01", "asset:3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.REJECTED
        assert "host:mail-relay-07" in report.unsupported_refs

    def test_an_invented_address_is_rejected(self):
        report = grounding.validate(
            "Traffic reaches 10.0.0.99 directly.",
            {"ip:192.168.10.14"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.REJECTED
        assert "ip:10.0.0.99" in report.unsupported_refs

    def test_a_record_may_be_cited_by_bare_uuid(self):
        """Retrieval hands back `finding:<uuid>`; an answer that writes the
        identifier without its type prefix is still citing that record."""
        record = "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"
        report = grounding.validate(
            f"Finding {record} is the one to fix first.",
            {f"finding:{record}"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.GROUNDED

    def test_a_cited_record_uuid_is_not_mistaken_for_a_hostname(self):
        """
        A UUID has the same shape as an inventory hostname — lowercase letters,
        digits and hyphens. Read as one, a correctly cited record identifier
        looks like an invented host and the whole answer is withheld. The
        extractor claims the more specific patterns first.
        """
        record = "ef4604ee-3e3d-410e-b387-1c3e018c3362"
        refs = grounding.extract_references(f"See finding {record}.")
        assert refs == {f"uuid:{record}"}

    def test_a_cve_identifier_is_not_also_read_as_a_hostname(self):
        refs = grounding.extract_references("CVE-2024-3094 applies here.")
        assert refs == {"cve:CVE-2024-3094"}

    def test_an_address_is_not_also_read_as_a_hostname(self):
        refs = grounding.extract_references("Reachable at 10.4.2.7 today.")
        assert refs == {"ip:10.4.2.7"}

    def test_a_host_may_be_cited_by_its_leftmost_label(self):
        report = grounding.validate(
            "db-prod-01 needs patching.",
            {"host:db-prod-01.corp.example.com"},
            retrieved_any=True,
        )
        assert report.status is GroundingStatus.GROUNDED

    def test_specifics_asserted_with_no_retrieval_at_all_are_rejected(self):
        report = grounding.validate(
            "Your environment has CVE-2024-3094 on three servers.",
            set(),
            retrieved_any=False,
        )
        assert report.status is GroundingStatus.REJECTED

    def test_saying_there_is_no_data_is_allowed_with_no_retrieval(self):
        report = grounding.validate(
            "No assessment has been run, so there is nothing to report.",
            set(),
            retrieved_any=False,
        )
        assert report.status is GroundingStatus.NO_EVIDENCE
        assert not report.unsupported_refs

    def test_the_rejection_notice_names_what_could_not_be_traced(self):
        report = grounding.validate(
            "CVE-2019-0708 is present.", {"cve:CVE-2024-3094"}, retrieved_any=True
        )
        notice = grounding.rejection_notice(report)
        assert "CVE-2019-0708" in notice
        # The withheld draft must never appear in what the operator is shown.
        assert "is present" not in notice

    def test_no_evidence_notice_is_the_refusal_sentence(self):
        report = grounding.validate("", set(), retrieved_any=False)
        assert grounding.rejection_notice(report) == grounding.INSUFFICIENT_EVIDENCE
        assert "sufficient evidence" in grounding.INSUFFICIENT_EVIDENCE

    def test_the_report_declares_what_it_does_not_check(self):
        """The check catches invented identifiers, not wrong totals. Claiming
        otherwise would be its own fabrication."""
        report = grounding.validate("Nothing specific.", {"asset:x"}, retrieved_any=True)
        payload = report.as_dict()
        assert "numeric totals" in payload["not_validated"]
        assert payload["not_validated_note"]
