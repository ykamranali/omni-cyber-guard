from pydantic import BaseModel


class ComponentStatus(BaseModel):
    name: str
    status: str  # "operational" | "degraded" | "down"
    detail: str = ""


class SystemStatusOut(BaseModel):
    overall_status: str
    components: list[ComponentStatus]


class NetworkInfoOut(BaseModel):
    client_ip: str
    server_local_ip: str
