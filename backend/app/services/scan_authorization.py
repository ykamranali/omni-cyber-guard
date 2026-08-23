"""
Authorized scope enforcement.

`Network.is_authorized_scope` is documented as "the record of consent: a scan
may only target a range an operator has explicitly declared they are authorized
to assess", and `sites.py` states that "discovery and scanning both consult
this table".

Neither did. `check_scan_authorization` existed and was advisory — the Scan
Centre called it to *display* a warning — but nothing acted on the answer.
`create_scan` validated only that the target was a private range of a sane
size, which stops a scan of the public internet and stops nothing else: any
authenticated user could scan any RFC1918 range, including one belonging to a
different tenant of the same physical network, whether or not their
organization had ever declared it in scope.

This module is now the one place that decides, and it is called at every point
a scan can start: the API, the scheduler, and domain probing.
"""
from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.network import Network


class AuthorizationError(PermissionError):
    """The target is not inside a range this organization declared in scope."""


@dataclass(frozen=True)
class AuthorizationCheck:
    authorized: bool
    target: str
    matched_network: dict | None
    message: str

    def as_dict(self) -> dict:
        return {
            "authorized": self.authorized,
            "target": self.target,
            "matched_network": self.matched_network,
            "message": self.message,
        }


NOT_AUTHORIZED_TEMPLATE = (
    "{target} is not inside any network this organization has marked as "
    "authorized scope. Register the range under Discovery → Networks and mark "
    "it authorized before scanning it. Scanning a range you have not been "
    "authorized to assess is not something this platform will do on your behalf."
)


def check_target(
    db: Session, *, organization_id: uuid.UUID, target: str
) -> AuthorizationCheck:
    """
    Decide whether `target` falls inside a declared, authorized range.

    Containment is strict: the requested range must be a subnet of a declared
    one. A declared /24 does not authorize the /16 that contains it.
    """
    cleaned = (target or "").strip()
    try:
        requested = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return AuthorizationCheck(
            authorized=False, target=cleaned, matched_network=None,
            message=f"'{cleaned}' is not a valid IP address or CIDR range.",
        )

    networks = db.execute(
        select(Network).where(Network.organization_id == organization_id)
    ).scalars().all()

    covering_but_unauthorized: Network | None = None

    for network in networks:
        try:
            declared = ipaddress.ip_network(network.cidr, strict=False)
        except ValueError:
            # A malformed stored range authorizes nothing. Skipped rather than
            # treated as a wildcard.
            continue
        if requested.version != declared.version:
            continue
        if not requested.subnet_of(declared):
            continue
        if network.is_authorized_scope:
            return AuthorizationCheck(
                authorized=True, target=cleaned,
                matched_network={
                    "id": str(network.id), "name": network.name, "cidr": network.cidr,
                },
                message=(
                    f"{cleaned} falls inside '{network.name}' ({network.cidr}), "
                    f"which is marked as authorized scope."
                ),
            )
        covering_but_unauthorized = network

    if covering_but_unauthorized is not None:
        return AuthorizationCheck(
            authorized=False, target=cleaned,
            matched_network={
                "id": str(covering_but_unauthorized.id),
                "name": covering_but_unauthorized.name,
                "cidr": covering_but_unauthorized.cidr,
            },
            message=(
                f"{cleaned} falls inside '{covering_but_unauthorized.name}' "
                f"({covering_but_unauthorized.cidr}), but that network is not "
                f"marked as authorized scope. Mark it authorized before scanning."
            ),
        )

    return AuthorizationCheck(
        authorized=False, target=cleaned, matched_network=None,
        message=NOT_AUTHORIZED_TEMPLATE.format(target=cleaned),
    )


def assert_target_authorized(
    db: Session, *, organization_id: uuid.UUID, target: str
) -> AuthorizationCheck:
    """Raise unless the target is inside a declared authorized range."""
    result = check_target(db, organization_id=organization_id, target=target)
    if not result.authorized:
        raise AuthorizationError(result.message)
    return result
