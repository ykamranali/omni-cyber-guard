from pydantic import BaseModel


class ComponentStatus(BaseModel):
    name: str
    status: str  # "operational" | "degraded" | "down"
    detail: str = ""


class SystemStatusOut(BaseModel):
    overall_status: str
    components: list[ComponentStatus]
