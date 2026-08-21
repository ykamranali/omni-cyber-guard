"""
The exposure engine.

A number an operator cannot interrogate is a number they will eventually stop
trusting. Every score this module produces therefore arrives with the list of
contributors that produced it, each naming the evidence behind it, and the
contributors sum exactly to the total. Clicking "87" answers "why 87".

Two design decisions follow from that:

* **Nothing is included that cannot be computed from real data.** Attack-path
  position and identity privilege are part of the intended model but there is
  no graph and no directory integration yet. Rather than quietly weighting them
  at zero — which would make the score look complete — the breakdown lists them
  as unavailable, with what would enable them. A reader can then see that the
  score is a partial view, and of what.

* **Severity is not risk.** CVSS says how bad exploitation would be. EPSS says
  how likely it is. A KEV listing says it is already happening. Internet
  exposure and business criticality say how much it matters here. Collapsing
  those into CVSS alone is what makes vulnerability queues unworkable, so each
  is a separate, separately-explained contributor.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset, Criticality, DataSensitivity
from app.models.asset_detail import AssetService
from app.models.finding import CLOSED_STATUSES, Confidence, Finding, FindingClass, Severity

# Ports whose exposure is a meaningful signal on its own.
HIGH_VALUE_PORTS = frozenset({22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017})


@dataclass
class Contributor:
    """One component of a score, with why it applied."""

    key: str
    label: str
    points: float
    #: What in the data produced this, in the operator's language.
    evidence: str

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "points": round(self.points, 1),
            "evidence": self.evidence,
        }


@dataclass
class UnavailableFactor:
    """A factor the model intends to use but cannot compute yet."""

    key: str
    label: str
    reason: str
    max_points: float

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "reason": self.reason,
            "max_points": self.max_points,
        }


@dataclass
class ExposureModel:
    """
    Weights for each contributor, capped at the maximum points it can add.

    Configurable per organization so a healthcare estate can weight data
    sensitivity above internet exposure, or an internet-facing SaaS estate the
    reverse. The defaults below are a starting point, not a claim of universal
    correctness.
    """

    vulnerability_severity: float = 20.0
    known_exploited: float = 20.0
    exploit_probability: float = 15.0
    internet_exposure: float = 15.0
    asset_criticality: float = 10.0
    data_sensitivity: float = 5.0
    finding_volume: float = 5.0
    exposure_duration: float = 5.0
    exposed_services: float = 5.0

    @property
    def maximum(self) -> float:
        return sum(asdict(self).values())

    @classmethod
    def from_organization(cls, organization) -> "ExposureModel":
        """Load an organization's weights, falling back to the defaults."""
        overrides = (getattr(organization, "exposure_model", None) or {}) if organization else {}
        defaults = asdict(cls())
        for key in defaults:
            value = overrides.get(key)
            if isinstance(value, (int, float)) and value >= 0:
                defaults[key] = float(value)
        return cls(**defaults)


@dataclass
class ExposureAssessment:
    """A computed score and the full reasoning behind it."""

    score: float
    band: str
    contributors: list[Contributor] = field(default_factory=list)
    unavailable: list[UnavailableFactor] = field(default_factory=list)
    computed_at: datetime | None = None
    #: Set when there is nothing to score, so the UI shows an empty state
    #: rather than a reassuring zero.
    assessed: bool = True
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "band": self.band,
            "assessed": self.assessed,
            "note": self.note,
            "contributors": [contributor.as_dict() for contributor in self.contributors],
            "unavailable_factors": [factor.as_dict() for factor in self.unavailable],
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
            "total_check": round(sum(c.points for c in self.contributors), 1),
        }


def band_for(score: float) -> str:
    if score >= 90:
        return "extreme"
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


# Factors the model intends to include once the data exists. Listed explicitly
# so a score never appears more complete than it is.
UNAVAILABLE_FACTORS = [
    UnavailableFactor(
        key="attack_path_position",
        label="Position on an attack path",
        reason=(
            "No exposure graph has been built yet, so it is not known whether this asset "
            "sits on a path toward a privileged resource."
        ),
        max_points=10.0,
    ),
    UnavailableFactor(
        key="identity_privilege",
        label="Privileged identity exposure",
        reason=(
            "No directory integration is configured, so the privilege held by accounts "
            "on this asset is unknown."
        ),
        max_points=7.0,
    ),
    UnavailableFactor(
        key="compensating_controls",
        label="Compensating controls",
        reason=(
            "No control inventory is recorded, so mitigations already in place cannot "
            "reduce this score."
        ),
        max_points=0.0,
    ),
]


def _severity_weight(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.7,
        Severity.MEDIUM: 0.4,
        Severity.LOW: 0.15,
        Severity.INFO: 0.0,
    }[severity]


def assess_asset(
    db: Session, asset: Asset, model: ExposureModel | None = None
) -> ExposureAssessment:
    """
    Score one asset's exposure and explain every point of it.

    Only open findings count. A remediated, accepted or false-positive finding
    has been dealt with, and continuing to score it would mean remediation
    never moved the number.
    """
    model = model or ExposureModel.from_organization(asset.organization)
    now = datetime.now(timezone.utc)

    findings = db.execute(
        select(Finding).where(
            Finding.asset_id == asset.id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
    ).scalars().all()

    contributors: list[Contributor] = []

    # --- 1. Worst open vulnerability ------------------------------------
    # Informational findings are excluded: recording a fact is not an exposure.
    material = [f for f in findings if f.finding_class is not FindingClass.INFORMATIONAL]
    if material:
        worst = max(material, key=lambda f: (_severity_weight(f.severity), f.cvss_score or 0))
        weight = _severity_weight(worst.severity)
        if weight > 0:
            points = model.vulnerability_severity * weight
            cvss = f", CVSS {worst.cvss_score}" if worst.cvss_score is not None else ""
            contributors.append(Contributor(
                key="vulnerability_severity",
                label="Most severe open finding",
                points=points,
                evidence=f"{worst.severity.value.upper()}{cvss}: {worst.title}",
            ))

    # --- 2. Known exploited in the wild ---------------------------------
    exploited = [f for f in findings if f.is_known_exploited]
    if exploited:
        contributors.append(Contributor(
            key="known_exploited",
            label="Known exploited in the wild",
            points=model.known_exploited,
            evidence=(
                f"{len(exploited)} finding(s) reference a CVE in the CISA KEV catalogue: "
                + ", ".join(sorted({f.cve_id for f in exploited if f.cve_id})[:5])
            ),
        ))

    # --- 3. Exploit probability -----------------------------------------
    scored = [f for f in findings if f.epss_score is not None]
    if scored:
        highest = max(scored, key=lambda f: f.epss_score or 0)
        probability = highest.epss_score or 0.0
        points = model.exploit_probability * probability
        if points >= 0.05:
            contributors.append(Contributor(
                key="exploit_probability",
                label="Exploit probability (EPSS)",
                points=points,
                evidence=(
                    f"{highest.cve_id} has a {probability * 100:.1f}% probability of "
                    f"exploitation in the next 30 days"
                ),
            ))

    # --- 4. Internet exposure -------------------------------------------
    if asset.is_internet_facing:
        contributors.append(Contributor(
            key="internet_exposure",
            label="Internet facing",
            points=model.internet_exposure,
            evidence=(
                "This asset sits in a network an operator declared as internet facing. "
                "Exposure is never inferred from the address."
            ),
        ))

    # --- 5. Business criticality ----------------------------------------
    criticality_weight = {
        Criticality.CRITICAL: 1.0,
        Criticality.HIGH: 0.7,
        Criticality.MEDIUM: 0.4,
        Criticality.LOW: 0.1,
        Criticality.UNASSIGNED: 0.0,
    }[asset.criticality]
    if criticality_weight > 0:
        contributors.append(Contributor(
            key="asset_criticality",
            label="Business criticality",
            points=model.asset_criticality * criticality_weight,
            evidence=f"Classified as {asset.criticality.value} by an operator",
        ))

    # --- 6. Data sensitivity --------------------------------------------
    sensitivity_weight = {
        DataSensitivity.RESTRICTED: 1.0,
        DataSensitivity.CONFIDENTIAL: 0.6,
        DataSensitivity.INTERNAL: 0.2,
        DataSensitivity.PUBLIC: 0.0,
        DataSensitivity.UNASSIGNED: 0.0,
    }[asset.data_sensitivity]
    if sensitivity_weight > 0:
        contributors.append(Contributor(
            key="data_sensitivity",
            label="Data sensitivity",
            points=model.data_sensitivity * sensitivity_weight,
            evidence=f"Holds {asset.data_sensitivity.value} data",
        ))

    # --- 7. Volume of open findings --------------------------------------
    severe = [f for f in material if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if severe:
        # Saturating, not linear: the tenth high-severity finding does not
        # double the exposure of the fifth.
        ratio = min(1.0, len(severe) / 10.0)
        contributors.append(Contributor(
            key="finding_volume",
            label="Volume of severe findings",
            points=model.finding_volume * ratio,
            evidence=f"{len(severe)} open critical or high-severity finding(s)",
        ))

    # --- 8. How long it has been open ------------------------------------
    if material:
        oldest = min(material, key=lambda f: f.first_seen)
        days_open = max(0, (now - oldest.first_seen).days)
        if days_open >= 7:
            ratio = min(1.0, days_open / 90.0)
            contributors.append(Contributor(
                key="exposure_duration",
                label="Time exposed",
                points=model.exposure_duration * ratio,
                evidence=f"Oldest open finding has been present for {days_open} day(s)",
            ))

    # --- 9. Exposed high-value services ----------------------------------
    exposed_ports = db.execute(
        select(AssetService.port).where(
            AssetService.asset_id == asset.id,
            AssetService.state == "open",
            AssetService.port.in_(sorted(HIGH_VALUE_PORTS)),
        )
    ).scalars().all()
    if exposed_ports:
        ratio = min(1.0, len(exposed_ports) / 4.0)
        contributors.append(Contributor(
            key="exposed_services",
            label="Exposed high-value services",
            points=model.exposed_services * ratio,
            evidence=(
                f"{len(exposed_ports)} high-value port(s) open: "
                + ", ".join(str(port) for port in sorted(exposed_ports))
            ),
        ))

    # A contributor worth zero points explains nothing and implies it counted.
    # This happens when an organization sets a factor's weight to zero, which is
    # a deliberate statement that it should not appear.
    contributors = [contributor for contributor in contributors if contributor.points > 0]

    total = sum(contributor.points for contributor in contributors)
    scaled = min(100.0, total * (100.0 / model.maximum)) if model.maximum else 0.0

    # Rescale the contributors so the displayed points still sum to the
    # displayed total. A breakdown that does not add up is worse than none.
    if total > 0 and scaled != total:
        factor = scaled / total
        for contributor in contributors:
            contributor.points *= factor

    assessed = bool(findings) or asset.is_internet_facing or asset.criticality is not Criticality.UNASSIGNED

    return ExposureAssessment(
        score=round(scaled, 1),
        band=band_for(scaled),
        contributors=sorted(contributors, key=lambda c: c.points, reverse=True),
        unavailable=list(UNAVAILABLE_FACTORS),
        computed_at=now,
        assessed=assessed,
        note=(
            "" if assessed else
            "This asset has no findings and no business context assigned, so there is "
            "nothing to score yet. A score of zero here means 'not assessed', not 'secure'."
        ),
    )


def recompute_asset_exposure(
    db: Session, asset: Asset, model: ExposureModel | None = None
) -> ExposureAssessment:
    """Score an asset and persist the result with its breakdown."""
    assessment = assess_asset(db, asset, model)
    asset.exposure_score = assessment.score
    asset.exposure_breakdown = assessment.as_dict()
    asset.exposure_calculated_at = assessment.computed_at
    db.add(asset)
    return assessment


def recompute_organization_exposure(db: Session, organization_id: uuid.UUID) -> dict:
    """
    Rescore every asset in an organization.

    The organization-level score is the mean of assets that were actually
    assessed. Averaging in unassessed assets would dilute the number toward
    zero and make an unscanned estate look safe.
    """
    from app.models.organization import Organization

    organization = db.execute(
        select(Organization).where(Organization.id == organization_id)
    ).scalar_one_or_none()
    model = ExposureModel.from_organization(organization)

    assets = db.execute(
        select(Asset).where(Asset.organization_id == organization_id)
    ).scalars().all()

    assessed_scores: list[float] = []
    for asset in assets:
        assessment = recompute_asset_exposure(db, asset, model)
        if assessment.assessed:
            assessed_scores.append(assessment.score)

    db.commit()

    return {
        "assets_total": len(assets),
        "assets_assessed": len(assessed_scores),
        "organization_exposure_score": (
            round(sum(assessed_scores) / len(assessed_scores), 1) if assessed_scores else None
        ),
        "note": (
            None if assessed_scores else
            "No asset has enough data to be scored yet. Run a scan, or assign business "
            "criticality, to produce an exposure score."
        ),
    }


def top_exposed_assets(db: Session, organization_id: uuid.UUID, limit: int = 10) -> list[Asset]:
    return db.execute(
        select(Asset)
        .where(Asset.organization_id == organization_id, Asset.exposure_score > 0)
        .order_by(Asset.exposure_score.desc())
        .limit(limit)
    ).scalars().all()
