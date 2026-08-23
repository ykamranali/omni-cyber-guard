"""
Cloud posture adapters.

Each adapter names the credentials it needs and the SDK it calls. None of them
is configured out of the box, and an unconfigured adapter returns a description
saying so — it does not invent a resource to represent its own absence.

The SDK imports are deliberately deferred into `discover()`. Declaring boto3 as
a hard dependency of the application would make every deployment carry it in
order to support an integration most deployments do not use, and an import
error at module load would take down the API rather than disabling one feature.
"""
from __future__ import annotations

from app.core.config import settings
from app.services.integrations.base import (
    AdapterDescription, AdapterError, DiscoveryResult,
)

IMPLEMENTED_IN = "backend/app/services/integrations/cloud.py"

WHY_REQUIRED = (
    "Cloud resource discovery reads the inventory from your cloud provider's "
    "own API. There is no way to enumerate it without credentials for that "
    "account, and the platform will not display resources it has not read."
)


class AwsAdapter:
    provider = "AWS"

    def describe(self) -> AdapterDescription:
        missing = [
            name for name, value in (
                ("AWS_ACCESS_KEY_ID", settings.AWS_ACCESS_KEY_ID),
                ("AWS_SECRET_ACCESS_KEY", settings.AWS_SECRET_ACCESS_KEY),
                ("AWS_REGION", settings.AWS_REGION),
            ) if not str(value or "").strip()
        ]
        return AdapterDescription(
            provider=self.provider,
            configured=not missing,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=(
                "Create a read-only IAM principal (the AWS managed policy "
                "SecurityAudit is sufficient), then set AWS_ACCESS_KEY_ID, "
                "AWS_SECRET_ACCESS_KEY and AWS_REGION in the backend "
                "environment and install the SDK with `pip install boto3`. "
                "Discovery calls ec2:DescribeInstances only and never writes."
            ) if missing else "",
            implemented_in=IMPLEMENTED_IN,
        )

    def discover(self) -> DiscoveryResult:
        try:
            import boto3  # noqa: PLC0415 — see module docstring
        except ImportError:
            raise AdapterError(
                "AWS credentials are configured but the boto3 SDK is not "
                "installed in this deployment. Install it with `pip install "
                "boto3` and restart the worker. No inventory has been recorded."
            )

        client = boto3.client(
            "ec2",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        records: list[dict] = []
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {
                        tag.get("Key"): tag.get("Value")
                        for tag in instance.get("Tags", [])
                    }
                    records.append({
                        "resource_type": "AWS::EC2::Instance",
                        "resource_id": instance.get("InstanceId", ""),
                        "name": tags.get("Name") or instance.get("InstanceId", ""),
                        "region": settings.AWS_REGION,
                        "status": (instance.get("State") or {}).get("name", "unknown"),
                    })
        return DiscoveryResult(
            succeeded=True, records=records,
            message=f"Read {len(records)} EC2 instance(s) from {settings.AWS_REGION}.",
        )


class AzureAdapter:
    provider = "Azure"

    def describe(self) -> AdapterDescription:
        missing = [
            name for name, value in (
                ("AZURE_TENANT_ID", settings.AZURE_TENANT_ID),
                ("AZURE_CLIENT_ID", settings.AZURE_CLIENT_ID),
                ("AZURE_CLIENT_SECRET", settings.AZURE_CLIENT_SECRET),
                ("AZURE_SUBSCRIPTION_ID", settings.AZURE_SUBSCRIPTION_ID),
            ) if not str(value or "").strip()
        ]
        return AdapterDescription(
            provider=self.provider,
            configured=not missing,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=(
                "Register an application in Entra ID, grant it the Reader role "
                "on the subscription, then set AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and "
                "AZURE_SUBSCRIPTION_ID, and install the SDK with `pip install "
                "azure-identity azure-mgmt-resource`."
            ) if missing else "",
            implemented_in=IMPLEMENTED_IN,
        )

    def discover(self) -> DiscoveryResult:
        try:
            from azure.identity import ClientSecretCredential  # noqa: PLC0415
            from azure.mgmt.resource import ResourceManagementClient  # noqa: PLC0415
        except ImportError:
            raise AdapterError(
                "Azure credentials are configured but the Azure SDK is not "
                "installed in this deployment. Install it with `pip install "
                "azure-identity azure-mgmt-resource` and restart the worker. "
                "No inventory has been recorded."
            )

        credential = ClientSecretCredential(
            tenant_id=settings.AZURE_TENANT_ID,
            client_id=settings.AZURE_CLIENT_ID,
            client_secret=settings.AZURE_CLIENT_SECRET,
        )
        client = ResourceManagementClient(credential, settings.AZURE_SUBSCRIPTION_ID)
        records = [
            {
                "resource_type": resource.type or "Azure::Resource",
                "resource_id": resource.id or "",
                "name": resource.name or "",
                "region": resource.location or "",
                "status": "present",
            }
            for resource in client.resources.list()
        ]
        return DiscoveryResult(
            succeeded=True, records=records,
            message=f"Read {len(records)} resource(s) from the subscription.",
        )


ADAPTERS = {adapter.provider.lower(): adapter for adapter in (AwsAdapter(), AzureAdapter())}


def get_adapter(provider: str):
    adapter = ADAPTERS.get(str(provider or "").strip().lower())
    if adapter is None:
        raise AdapterError(
            f"{provider!r} is not a cloud provider this platform integrates with. "
            f"Available: {', '.join(sorted(a.provider for a in ADAPTERS.values()))}."
        )
    return adapter
