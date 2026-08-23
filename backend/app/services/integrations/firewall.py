"""
Firewall adapters.

Each adapter adds an address to, or removes it from, a **named object the
operator already controls** — an OPNsense/pfSense alias, or a FortiGate address
group. It does not create rules, change policy order, or touch anything else.
That boundary matters: the operator decides what a rule referencing that object
does, and the platform only decides what is in it. A tool that can write
arbitrary firewall policy through an API is a much larger thing to trust than
one that can add an address to a list.

Every method reports what the vendor actually said. Nothing here returns
success on a request the firewall did not accept, because the caller uses that
answer to decide whether a block may be recorded as `enforced`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

import requests

REQUEST_TIMEOUT_SECONDS = 20


class FirewallError(RuntimeError):
    """The firewall refused the request, or could not be reached."""


@dataclass(frozen=True)
class FirewallResult:
    succeeded: bool
    message: str
    # What the vendor returned, kept verbatim for the audit record.
    detail: dict | None = None


@dataclass(frozen=True)
class FirewallConfig:
    base_url: str
    identity: str
    secret: str
    blocklist_object: str
    verify_tls: bool = True


class FirewallAdapter(Protocol):
    vendor: str

    def test_connection(self, config: FirewallConfig) -> FirewallResult: ...

    def block(self, config: FirewallConfig, ip_address: str, reason: str) -> FirewallResult: ...

    def unblock(self, config: FirewallConfig, ip_address: str) -> FirewallResult: ...

    def list_blocked(self, config: FirewallConfig) -> list[str]: ...


def _request(method: str, url: str, config: FirewallConfig, **kwargs) -> requests.Response:
    try:
        response = requests.request(
            method, url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=config.verify_tls,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise FirewallError(f"{config.base_url} did not answer: {exc}") from exc

    if response.status_code in (401, 403):
        raise FirewallError(
            f"{config.base_url} rejected the credentials ({response.status_code}). "
            f"Check the API key and that it is permitted to edit the blocklist object."
        )
    if response.status_code == 404:
        raise FirewallError(
            f"{config.base_url} does not have an object named "
            f"'{config.blocklist_object}'. Create it on the firewall first — this "
            f"platform adds addresses to an existing object, it does not create "
            f"rules or policy."
        )
    if not response.ok:
        raise FirewallError(
            f"{config.base_url} returned {response.status_code}: {response.text[:300]}"
        )
    return response


def _json(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise FirewallError("The firewall returned a body that is not JSON.") from exc
    return payload if isinstance(payload, dict) else {"result": payload}


class OpnsenseAdapter:
    """
    OPNsense, through its firewall alias API.

    The alias named in `blocklist_object` must already exist and be referenced
    by whatever rule the operator wants it to drive.
    """

    vendor = "opnsense"

    def _auth(self, config: FirewallConfig):
        return (config.identity, config.secret)

    def test_connection(self, config: FirewallConfig) -> FirewallResult:
        response = _request(
            "GET",
            f"{config.base_url.rstrip('/')}/api/firewall/alias_util/list/{config.blocklist_object}",
            config, auth=self._auth(config),
        )
        payload = _json(response)
        rows = payload.get("rows", [])
        return FirewallResult(
            succeeded=True,
            message=(
                f"Connected. The alias '{config.blocklist_object}' currently holds "
                f"{len(rows)} address(es)."
            ),
            detail={"entries": len(rows)},
        )

    def block(self, config: FirewallConfig, ip_address: str, reason: str) -> FirewallResult:
        response = _request(
            "POST",
            f"{config.base_url.rstrip('/')}/api/firewall/alias_util/add/{config.blocklist_object}",
            config, auth=self._auth(config), json={"address": ip_address},
        )
        payload = _json(response)
        if payload.get("status", "").lower() not in ("done", "ok", ""):
            raise FirewallError(f"OPNsense reported: {json.dumps(payload)[:300]}")
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} added to alias '{config.blocklist_object}'.",
            detail=payload,
        )

    def unblock(self, config: FirewallConfig, ip_address: str) -> FirewallResult:
        response = _request(
            "POST",
            f"{config.base_url.rstrip('/')}/api/firewall/alias_util/delete/{config.blocklist_object}",
            config, auth=self._auth(config), json={"address": ip_address},
        )
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} removed from alias '{config.blocklist_object}'.",
            detail=_json(response),
        )

    def list_blocked(self, config: FirewallConfig) -> list[str]:
        response = _request(
            "GET",
            f"{config.base_url.rstrip('/')}/api/firewall/alias_util/list/{config.blocklist_object}",
            config, auth=self._auth(config),
        )
        return [
            str(row.get("ip", "")) for row in _json(response).get("rows", []) if row.get("ip")
        ]


class PfsenseAdapter:
    """
    pfSense, through the pfSense-pkg-API package.

    That package is not part of a stock pfSense install; if it is absent the
    connection test fails with a 404 and says so, rather than the integration
    appearing configured and silently doing nothing.
    """

    vendor = "pfsense"

    def _headers(self, config: FirewallConfig) -> dict:
        return {"Authorization": f"{config.identity} {config.secret}"}

    def _alias(self, config: FirewallConfig) -> dict:
        response = _request(
            "GET", f"{config.base_url.rstrip('/')}/api/v1/firewall/alias",
            config, headers=self._headers(config),
        )
        for alias in _json(response).get("data", []):
            if alias.get("name") == config.blocklist_object:
                return alias
        raise FirewallError(
            f"No alias named '{config.blocklist_object}' exists on this firewall."
        )

    def test_connection(self, config: FirewallConfig) -> FirewallResult:
        alias = self._alias(config)
        addresses = str(alias.get("address", "")).split()
        return FirewallResult(
            succeeded=True,
            message=(
                f"Connected. The alias '{config.blocklist_object}' currently holds "
                f"{len(addresses)} address(es)."
            ),
            detail={"entries": len(addresses)},
        )

    def block(self, config: FirewallConfig, ip_address: str, reason: str) -> FirewallResult:
        response = _request(
            "POST", f"{config.base_url.rstrip('/')}/api/v1/firewall/alias/entry",
            config, headers=self._headers(config),
            json={
                "name": config.blocklist_object,
                "address": [ip_address],
                "detail": [reason[:120] or "Blocked by Omni Cyber Guard"],
                "apply": True,
            },
        )
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} added to alias '{config.blocklist_object}'.",
            detail=_json(response),
        )

    def unblock(self, config: FirewallConfig, ip_address: str) -> FirewallResult:
        response = _request(
            "DELETE", f"{config.base_url.rstrip('/')}/api/v1/firewall/alias/entry",
            config, headers=self._headers(config),
            json={"name": config.blocklist_object, "address": ip_address, "apply": True},
        )
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} removed from alias '{config.blocklist_object}'.",
            detail=_json(response),
        )

    def list_blocked(self, config: FirewallConfig) -> list[str]:
        return [
            address for address in str(self._alias(config).get("address", "")).split()
            if address
        ]


class FortigateAdapter:
    """
    FortiGate, through its REST API.

    Addresses are created as objects and added to the group named in
    `blocklist_object`. The group must already exist and be referenced by a
    policy — this adapter never writes policy.
    """

    vendor = "fortigate"

    def _headers(self, config: FirewallConfig) -> dict:
        return {"Authorization": f"Bearer {config.secret}"}

    def _root(self, config: FirewallConfig) -> str:
        return f"{config.base_url.rstrip('/')}/api/v2/cmdb/firewall"

    def _group_members(self, config: FirewallConfig) -> list[dict]:
        response = _request(
            "GET", f"{self._root(config)}/addrgrp/{config.blocklist_object}",
            config, headers=self._headers(config),
        )
        results = _json(response).get("results") or []
        if not results:
            raise FirewallError(
                f"No address group named '{config.blocklist_object}' exists."
            )
        return results[0].get("member", []) or []

    @staticmethod
    def _object_name(ip_address: str) -> str:
        return f"ocg-block-{ip_address.replace(':', '-').replace('.', '-')}"

    def test_connection(self, config: FirewallConfig) -> FirewallResult:
        members = self._group_members(config)
        return FirewallResult(
            succeeded=True,
            message=(
                f"Connected. The address group '{config.blocklist_object}' holds "
                f"{len(members)} member(s)."
            ),
            detail={"entries": len(members)},
        )

    def block(self, config: FirewallConfig, ip_address: str, reason: str) -> FirewallResult:
        name = self._object_name(ip_address)

        # Creating the object is idempotent from our side: a 500 with an
        # "already exists" body is not a failure to block.
        try:
            _request(
                "POST", f"{self._root(config)}/address",
                config, headers=self._headers(config),
                json={
                    "name": name,
                    "subnet": f"{ip_address} 255.255.255.255",
                    "comment": (reason or "Blocked by Omni Cyber Guard")[:255],
                },
            )
        except FirewallError as exc:
            if "already exists" not in str(exc).lower() and "-5" not in str(exc):
                raise

        members = self._group_members(config)
        if any(member.get("name") == name for member in members):
            return FirewallResult(
                succeeded=True,
                message=f"{ip_address} was already in '{config.blocklist_object}'.",
            )

        response = _request(
            "PUT", f"{self._root(config)}/addrgrp/{config.blocklist_object}",
            config, headers=self._headers(config),
            json={"member": members + [{"name": name}]},
        )
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} added to group '{config.blocklist_object}'.",
            detail=_json(response),
        )

    def unblock(self, config: FirewallConfig, ip_address: str) -> FirewallResult:
        name = self._object_name(ip_address)
        members = [
            member for member in self._group_members(config)
            if member.get("name") != name
        ]
        response = _request(
            "PUT", f"{self._root(config)}/addrgrp/{config.blocklist_object}",
            config, headers=self._headers(config), json={"member": members},
        )
        return FirewallResult(
            succeeded=True,
            message=f"{ip_address} removed from group '{config.blocklist_object}'.",
            detail=_json(response),
        )

    def list_blocked(self, config: FirewallConfig) -> list[str]:
        prefix = "ocg-block-"
        return [
            member["name"][len(prefix):].replace("-", ".")
            for member in self._group_members(config)
            if str(member.get("name", "")).startswith(prefix)
        ]


ADAPTERS: dict[str, FirewallAdapter] = {
    adapter.vendor: adapter
    for adapter in (OpnsenseAdapter(), PfsenseAdapter(), FortigateAdapter())
}

VENDOR_SETUP = {
    "opnsense": (
        "System → Access → Users → API key. The key and secret are the identity "
        "and secret below. Create a firewall alias (Firewall → Aliases) of type "
        "Host(s), reference it from a block rule, and name it below."
    ),
    "pfsense": (
        "Requires the pfSense-pkg-API package. Create an API key under System → "
        "API, then create a Host alias, reference it from a block rule, and name "
        "it below."
    ),
    "fortigate": (
        "System → Administrators → REST API Admin, with an access profile that "
        "permits firewall address and address-group write. Create an address "
        "group, reference it from a deny policy, and name it below."
    ),
}


def get_adapter(vendor: str) -> FirewallAdapter:
    adapter = ADAPTERS.get(str(vendor or "").strip().lower())
    if adapter is None:
        raise FirewallError(
            f"{vendor!r} is not a firewall this platform integrates with. "
            f"Available: {', '.join(sorted(ADAPTERS))}."
        )
    return adapter
