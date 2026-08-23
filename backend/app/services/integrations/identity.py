"""
Identity provider adapters.

Same contract as the cloud adapters, and the same rule: an unconfigured
integration reports itself as unconfigured. It does not write an identity.

The previous implementation, on finding no configuration, inserted a profile
with the email `admin_integration_failed@okta.local` and the display name
"Integration Error: OAuth/SAML configuration missing". That row was returned by
the identity endpoint as a discovered corporate account.
"""
from __future__ import annotations

from app.core.config import settings
from app.services.integrations.base import (
    AdapterDescription, AdapterError, DiscoveryResult,
)

IMPLEMENTED_IN = "backend/app/services/integrations/identity.py"

WHY_REQUIRED = (
    "Identity discovery reads accounts, privilege levels and MFA enrolment "
    "from your directory's own API. Without credentials for it there is "
    "nothing to read, and the platform will not display accounts it has not "
    "read."
)

REQUEST_TIMEOUT_SECONDS = 30
PAGE_LIMIT = 200


class OktaAdapter:
    provider = "Okta"

    def describe(self) -> AdapterDescription:
        missing = [
            name for name, value in (
                ("OKTA_ORG_URL", settings.OKTA_ORG_URL),
                ("OKTA_API_TOKEN", settings.OKTA_API_TOKEN),
            ) if not str(value or "").strip()
        ]
        return AdapterDescription(
            provider=self.provider,
            configured=not missing,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=(
                "Create a read-only API token in the Okta admin console "
                "(Security → API → Tokens), then set OKTA_ORG_URL "
                "(https://your-org.okta.com) and OKTA_API_TOKEN in the backend "
                "environment. Discovery issues GET /api/v1/users only."
            ) if missing else "",
            implemented_in=IMPLEMENTED_IN,
        )

    def discover(self) -> DiscoveryResult:
        import requests  # noqa: PLC0415

        base = settings.OKTA_ORG_URL.rstrip("/")
        headers = {
            "Authorization": f"SSWS {settings.OKTA_API_TOKEN}",
            "Accept": "application/json",
        }
        try:
            response = requests.get(
                f"{base}/api/v1/users",
                headers=headers,
                params={"limit": PAGE_LIMIT},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise AdapterError(f"{base} did not answer: {exc}") from exc
        except ValueError as exc:
            raise AdapterError(f"{base} returned a body that is not JSON.") from exc

        if not isinstance(payload, list):
            raise AdapterError("The Okta users endpoint returned an unexpected shape.")

        records = []
        for entry in payload:
            profile = entry.get("profile") or {}
            records.append({
                "email": profile.get("email") or profile.get("login") or "",
                "full_name": " ".join(
                    part for part in (profile.get("firstName"), profile.get("lastName")) if part
                ),
                "is_active": entry.get("status") == "ACTIVE",
                # Okta does not return factor enrolment on the users listing.
                # Left unknown rather than guessed; see the model comment.
                "mfa_enabled": None,
                "last_login": entry.get("lastLogin"),
                "privilege_level": None,
            })
        return DiscoveryResult(
            succeeded=True, records=records,
            message=(
                f"Read {len(records)} account(s). MFA enrolment and privilege "
                f"level are not on this endpoint and are recorded as unknown."
            ),
        )


class EntraIdAdapter:
    provider = "Entra ID"

    def describe(self) -> AdapterDescription:
        missing = [
            name for name, value in (
                ("AZURE_TENANT_ID", settings.AZURE_TENANT_ID),
                ("AZURE_CLIENT_ID", settings.AZURE_CLIENT_ID),
                ("AZURE_CLIENT_SECRET", settings.AZURE_CLIENT_SECRET),
            ) if not str(value or "").strip()
        ]
        return AdapterDescription(
            provider=self.provider,
            configured=not missing,
            missing=missing,
            why_required=WHY_REQUIRED if missing else "",
            how_to_enable=(
                "Register an application in Entra ID with the application "
                "permission User.Read.All (admin consented), then set "
                "AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET in "
                "the backend environment. Discovery issues GET /v1.0/users "
                "against Microsoft Graph only."
            ) if missing else "",
            implemented_in=IMPLEMENTED_IN,
        )

    def discover(self) -> DiscoveryResult:
        import requests  # noqa: PLC0415

        try:
            token_response = requests.post(
                f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/oauth2/v2.0/token",
                data={
                    "client_id": settings.AZURE_CLIENT_ID,
                    "client_secret": settings.AZURE_CLIENT_SECRET,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
        except requests.RequestException as exc:
            raise AdapterError(f"Entra ID token request failed: {exc}") from exc
        except ValueError as exc:
            raise AdapterError("Entra ID returned a token body that is not JSON.") from exc

        if not access_token:
            raise AdapterError("Entra ID accepted the request but returned no access token.")

        try:
            response = requests.get(
                "https://graph.microsoft.com/v1.0/users",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"$top": PAGE_LIMIT},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise AdapterError(f"Microsoft Graph did not answer: {exc}") from exc
        except ValueError as exc:
            raise AdapterError("Microsoft Graph returned a body that is not JSON.") from exc

        records = [
            {
                "email": entry.get("mail") or entry.get("userPrincipalName") or "",
                "full_name": entry.get("displayName") or "",
                "is_active": entry.get("accountEnabled", True),
                "mfa_enabled": None,
                "last_login": None,
                "privilege_level": None,
            }
            for entry in payload.get("value", [])
        ]
        return DiscoveryResult(
            succeeded=True, records=records,
            message=(
                f"Read {len(records)} account(s). MFA enrolment requires the "
                f"reporting API and is recorded as unknown."
            ),
        )


ADAPTERS = {adapter.provider.lower(): adapter for adapter in (OktaAdapter(), EntraIdAdapter())}


def get_adapter(provider: str):
    adapter = ADAPTERS.get(str(provider or "").strip().lower())
    if adapter is None:
        raise AdapterError(
            f"{provider!r} is not an identity provider this platform integrates "
            f"with. Available: "
            f"{', '.join(sorted(a.provider for a in ADAPTERS.values()))}."
        )
    return adapter
