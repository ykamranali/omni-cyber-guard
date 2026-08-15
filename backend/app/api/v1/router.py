from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth, users, organizations, assets, findings, dashboard, scans, compliance, system,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(organizations.router)
api_router.include_router(assets.router)
api_router.include_router(findings.router)
api_router.include_router(dashboard.router)
api_router.include_router(scans.router)
api_router.include_router(compliance.router)
api_router.include_router(system.router)
