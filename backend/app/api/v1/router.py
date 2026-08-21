from fastapi import APIRouter

from app.api.v1.endpoints import (
    agent,
    assets,
    audit_logs,
    auth,
    compliance,
    dashboard,
    findings,
    organizations,
    reports,
    scans,
    system,
    threat_intel,
    users,
    incidents,
    infrastructure,
    intelligence,
    schedules,
    sites,
    credentials,
    vulnerability_intel,
    exposure,
    remediation,
    ws,
    graph,
    attack_paths,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(ws.router)
api_router.include_router(users.router)
api_router.include_router(organizations.router)
api_router.include_router(assets.router)
api_router.include_router(sites.router)
api_router.include_router(credentials.router)
api_router.include_router(findings.router)
api_router.include_router(scans.router)
api_router.include_router(dashboard.router)
api_router.include_router(exposure.router)
api_router.include_router(remediation.router)
api_router.include_router(audit_logs.router)
api_router.include_router(compliance.router)
api_router.include_router(threat_intel.router)
api_router.include_router(reports.router)
api_router.include_router(system.router)
api_router.include_router(agent.router)
api_router.include_router(incidents.router)
api_router.include_router(infrastructure.router)
api_router.include_router(intelligence.router)
api_router.include_router(vulnerability_intel.router)
api_router.include_router(schedules.router, prefix="/schedules", tags=["schedules"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
api_router.include_router(attack_paths.router, prefix="/attack-paths", tags=["attack-paths"])
