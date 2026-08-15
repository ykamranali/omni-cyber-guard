from pydantic import BaseModel


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class DashboardSummary(BaseModel):
    security_score: float
    risk_score: float
    findings_by_severity: SeverityCounts
    total_assets: int
    active_assets: int
    asset_health_percent: float
    compliance_status: dict[str, float]
    remediation_progress_percent: float
    open_findings: int
    remediated_findings_last_30_days: int


class TrendPoint(BaseModel):
    date: str
    security_score: float
    risk_score: float
    open_findings: int
