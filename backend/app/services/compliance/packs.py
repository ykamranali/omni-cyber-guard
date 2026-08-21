"""
Compliance content packs.

Every control here is either mapped to a check the platform can genuinely
evaluate, or explicitly MANUAL. Nothing is included that would be silently
scored as passing because the platform has no opinion.

These packs are **original control sets inspired by the structure of published
frameworks**, mapped to the signals this platform actually collects. They are
not the published control text, and installing one does not make an
organization certified against anything. Where a framework requires evidence
this platform does not gather — physical security, personnel screening, vendor
management — the control is present as MANUAL so it is visible as an
outstanding obligation rather than absent from the checklist entirely.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.compliance import (
    CheckType, ComplianceControl, ComplianceFramework, ComplianceRequirement,
)

# A control entry: (code, title, description, check_type, parameters, guidance)
ControlSpec = dict[str, Any]


def _control(
    code: str,
    title: str,
    description: str,
    check_type: CheckType,
    parameters: dict | None = None,
    guidance: str = "",
) -> ControlSpec:
    return {
        "code": code,
        "title": title,
        "description": description,
        "check_type": check_type,
        "parameters": parameters or {},
        "guidance": guidance,
    }


NETWORK_HYGIENE = {
    "slug": "network-hygiene",
    "name": "Network Hygiene Baseline",
    "version": "1.0",
    "source": "Omni Cyber Guard — original control set",
    "description": (
        "A minimal, fully-automatable baseline. Every control here is evaluated "
        "from scan data, so this framework has no unassessable controls."
    ),
    "requirements": [
        {
            "code": "NH-1",
            "title": "Insecure protocols are not in use",
            "description": "Cleartext administrative and file-transfer protocols are disabled.",
            "controls": [
                _control(
                    "NH-1.1", "Telnet is not exposed",
                    "No asset exposes TCP/23. Telnet transmits credentials in cleartext.",
                    CheckType.NO_EXPOSED_PORT, {"ports": [23]},
                    "Replace Telnet with SSH and disable the Telnet service.",
                ),
                _control(
                    "NH-1.2", "Cleartext FTP is not exposed",
                    "No asset exposes TCP/21.",
                    CheckType.NO_EXPOSED_PORT, {"ports": [21]},
                    "Use SFTP or FTPS, or restrict FTP to trusted hosts only.",
                ),
                _control(
                    "NH-1.3", "Legacy SMB and NetBIOS are not exposed",
                    "No asset exposes TCP/139. NetBIOS session service is a lateral-movement vector.",
                    CheckType.NO_EXPOSED_PORT, {"ports": [139]},
                    "Disable NetBIOS over TCP/IP where it is not required.",
                ),
                _control(
                    "NH-1.4", "Unauthenticated remote desktop is not internet facing",
                    "No internet-facing asset exposes TCP/3389.",
                    CheckType.NO_EXPOSED_PORT, {"ports": [3389], "internet_facing_only": True},
                    "Place RDP behind a VPN and enforce multi-factor authentication.",
                ),
            ],
        },
        {
            "code": "NH-2",
            "title": "Databases are not directly exposed",
            "description": "Database services are reachable only from application tiers.",
            "controls": [
                _control(
                    "NH-2.1", "Database ports are not internet facing",
                    "No internet-facing asset exposes a common database port.",
                    CheckType.NO_EXPOSED_PORT,
                    {"ports": [1433, 3306, 5432, 27017, 6379], "internet_facing_only": True},
                    "Restrict database listeners to application subnets; never expose them publicly.",
                ),
            ],
        },
        {
            "code": "NH-3",
            "title": "The estate is actually assessed",
            "description": (
                "Controls are only meaningful over assets that have been looked at. "
                "These verify the assessment itself is current."
            ),
            "controls": [
                _control(
                    "NH-3.1", "Every asset has been assessed in the last 30 days",
                    "An asset not scanned recently has an unknown posture, not a good one.",
                    CheckType.ASSESSMENT_FRESHNESS, {"max_age_days": 30},
                    "Schedule recurring scans covering every authorized network.",
                ),
                _control(
                    "NH-3.2", "Every asset has a business criticality assigned",
                    "Criticality drives prioritisation; an unassigned asset is scored on "
                    "technical signal alone.",
                    CheckType.ASSET_ATTRIBUTE_REQUIRED, {"attribute": "criticality"},
                    "Set criticality from each asset's detail panel.",
                ),
            ],
        },
        {
            "code": "NH-4",
            "title": "Findings are remediated in reasonable time",
            "description": "Open findings do not accumulate indefinitely.",
            "controls": [
                _control(
                    "NH-4.1", "No critical finding open longer than 7 days",
                    "",
                    CheckType.REMEDIATION_WITHIN_SLA, {"severity": "critical", "max_age_days": 7},
                    "Open remediation tasks for critical findings and track them to verification.",
                ),
                _control(
                    "NH-4.2", "No high-severity finding open longer than 30 days",
                    "",
                    CheckType.REMEDIATION_WITHIN_SLA, {"severity": "high", "max_age_days": 30},
                ),
                _control(
                    "NH-4.3", "No high-severity finding on an internet-facing asset",
                    "",
                    CheckType.NO_EXPOSED_SEVERITY, {"severity": "high"},
                    "Prioritise internet-facing assets; they have no network boundary protecting them.",
                ),
            ],
        },
    ],
}


HOST_HARDENING = {
    "slug": "host-hardening",
    "name": "Host Hardening Baseline",
    "version": "1.0",
    "source": "Omni Cyber Guard — original control set, evaluated from credentialed scan results",
    "description": (
        "Configuration controls evaluated from credentialed Windows and Linux audits. "
        "Controls here stay NOT_ASSESSED until a credentialed scan has run — an "
        "unauthenticated scan cannot see host configuration."
    ),
    "requirements": [
        {
            "code": "HH-1",
            "title": "Legacy protocols are disabled on hosts",
            "description": "",
            "controls": [
                _control(
                    "HH-1.1", "SMBv1 is disabled",
                    "SMBv1 has a long history of remotely exploitable flaws.",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "windows_audit", "check_ids": ["smbv1-enabled", "SMBv1"]},
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                ),
            ],
        },
        {
            "code": "HH-2",
            "title": "Endpoint protection is active",
            "description": "",
            "controls": [
                _control(
                    "HH-2.1", "Anti-malware is enabled",
                    "",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "windows_audit", "check_ids": ["defender-disabled", "Defender"]},
                    "Re-enable Microsoft Defender, or confirm an approved third-party product manages the host.",
                ),
                _control(
                    "HH-2.2", "The host firewall is enabled",
                    "",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "windows_audit", "check_ids": ["firewall-domain-off", "firewall"]},
                ),
            ],
        },
        {
            "code": "HH-3",
            "title": "Authentication is enforced at the host",
            "description": "",
            "controls": [
                _control(
                    "HH-3.1", "Remote Desktop requires Network Level Authentication",
                    "",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "windows_audit", "check_ids": ["rdp-nla-disabled", "NLA"]},
                ),
                _control(
                    "HH-3.2", "Automatic logon is not configured",
                    "AutoAdminLogon typically means a password is stored in the registry in cleartext.",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "windows_audit", "check_ids": ["autologon-enabled", "autologon"]},
                ),
            ],
        },
        {
            "code": "HH-4",
            "title": "Linux hosts follow a hardening baseline",
            "description": "",
            "controls": [
                _control(
                    "HH-4.1", "No high-severity Lynis warnings outstanding",
                    "",
                    CheckType.NO_OPEN_FINDING,
                    {"source": "lynis", "check_ids": ["SSH-", "AUTH-", "FILE-"]},
                    "Review the named Lynis tests and apply the recommended hardening.",
                ),
            ],
        },
    ],
}


GOVERNANCE_BASELINE = {
    "slug": "governance-baseline",
    "name": "Security Governance Baseline",
    "version": "1.0",
    "source": "Omni Cyber Guard — original control set",
    "description": (
        "Governance obligations. Several of these cannot be evaluated from scan data "
        "and are recorded as manual controls requiring an attestation — they appear "
        "as outstanding rather than being quietly omitted from the checklist."
    ),
    "requirements": [
        {
            "code": "GV-1",
            "title": "Asset inventory is maintained",
            "description": "",
            "controls": [
                _control(
                    "GV-1.1", "Every asset is assigned an owner",
                    "",
                    CheckType.ASSET_ATTRIBUTE_REQUIRED, {"attribute": "business_owner"},
                ),
                _control(
                    "GV-1.2", "Every asset has a data sensitivity classification",
                    "",
                    CheckType.ASSET_ATTRIBUTE_REQUIRED, {"attribute": "data_sensitivity"},
                ),
            ],
        },
        {
            "code": "GV-2",
            "title": "Obligations this platform cannot evidence",
            "description": (
                "Controls requiring evidence outside this platform's reach. They are "
                "listed so the gap is visible; each needs a dated attestation."
            ),
            "controls": [
                _control(
                    "GV-2.1", "Security awareness training is delivered annually",
                    "Requires evidence from a training system this platform does not integrate with.",
                    CheckType.MANUAL, {},
                    "Record an attestation referencing your training completion report.",
                ),
                _control(
                    "GV-2.2", "Backups are taken and restoration is tested",
                    "Requires evidence from backup infrastructure this platform does not integrate with.",
                    CheckType.MANUAL, {},
                    "Record an attestation referencing your most recent restoration test.",
                ),
                _control(
                    "GV-2.3", "An incident response plan exists and is exercised",
                    "",
                    CheckType.MANUAL, {},
                    "Record an attestation referencing your most recent tabletop exercise.",
                ),
                _control(
                    "GV-2.4", "Physical access to server areas is controlled",
                    "",
                    CheckType.MANUAL, {},
                ),
                _control(
                    "GV-2.5", "Third-party access is reviewed periodically",
                    "",
                    CheckType.MANUAL, {},
                ),
            ],
        },
    ],
}


CONTENT_PACKS = {
    pack["slug"]: pack
    for pack in (NETWORK_HYGIENE, HOST_HARDENING, GOVERNANCE_BASELINE)
}


def install_pack(
    db: Session, organization_id: uuid.UUID, slug: str
) -> ComplianceFramework:
    """
    Install a content pack for an organization.

    Re-installing updates the control definitions in place, so a pack revision
    does not orphan existing results.
    """
    pack = CONTENT_PACKS.get(slug)
    if pack is None:
        raise ValueError(
            f"Unknown content pack '{slug}'. Available: {', '.join(sorted(CONTENT_PACKS))}."
        )

    framework = db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.organization_id == organization_id,
            ComplianceFramework.slug == slug,
        )
    ).scalar_one_or_none()

    if framework is None:
        framework = ComplianceFramework(
            organization_id=organization_id,
            slug=slug,
            name=pack["name"],
        )
        db.add(framework)

    framework.name = pack["name"]
    framework.version = pack["version"]
    framework.description = pack["description"]
    framework.source = pack["source"]
    framework.is_enabled = True
    db.flush()

    for order, requirement_spec in enumerate(pack["requirements"]):
        requirement = db.execute(
            select(ComplianceRequirement).where(
                ComplianceRequirement.framework_id == framework.id,
                ComplianceRequirement.code == requirement_spec["code"],
            )
        ).scalar_one_or_none()

        if requirement is None:
            requirement = ComplianceRequirement(
                framework_id=framework.id, code=requirement_spec["code"]
            )
            db.add(requirement)

        requirement.title = requirement_spec["title"]
        requirement.description = requirement_spec["description"]
        requirement.display_order = order
        db.flush()

        for control_spec in requirement_spec["controls"]:
            control = db.execute(
                select(ComplianceControl).where(
                    ComplianceControl.requirement_id == requirement.id,
                    ComplianceControl.code == control_spec["code"],
                )
            ).scalar_one_or_none()

            if control is None:
                control = ComplianceControl(
                    requirement_id=requirement.id, code=control_spec["code"]
                )
                db.add(control)

            control.title = control_spec["title"]
            control.description = control_spec["description"]
            control.guidance = control_spec["guidance"]
            control.check_type = control_spec["check_type"]
            control.check_parameters = control_spec["parameters"]
            db.flush()

    db.commit()
    return framework


def available_packs() -> list[dict[str, Any]]:
    """Summarise the packs, including how much of each can be automated."""
    summaries = []
    for slug, pack in CONTENT_PACKS.items():
        controls = [
            control
            for requirement in pack["requirements"]
            for control in requirement["controls"]
        ]
        automated = [c for c in controls if c["check_type"] is not CheckType.MANUAL]
        summaries.append({
            "slug": slug,
            "name": pack["name"],
            "version": pack["version"],
            "description": pack["description"],
            "source": pack["source"],
            "requirement_count": len(pack["requirements"]),
            "control_count": len(controls),
            "automated_control_count": len(automated),
            # Stated up front: a pack that is 40% manual will never report a
            # high assessable percentage without attestations being recorded.
            "manual_control_count": len(controls) - len(automated),
        })
    return sorted(summaries, key=lambda item: item["name"])
