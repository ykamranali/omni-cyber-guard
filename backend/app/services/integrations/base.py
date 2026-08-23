"""
Discovery adapter contract.

An adapter's job is to answer two questions honestly: *can I run?* and, if so,
*what did I actually find?* It is never allowed to answer the second question
when the answer to the first is no.

`describe()` reports configuration state without contacting anything, so the UI
can render "not configured" without a network round trip. `discover()` is only
called when `describe().configured` is true, and returns either real records or
a failure — never a substitute record standing in for one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class AdapterError(RuntimeError):
    """The integration is configured but the attempt failed."""


@dataclass(frozen=True)
class AdapterDescription:
    """
    Whether this adapter can run, and what is missing if it cannot.

    The fields after `configured` exist because the master specification
    requires an unavailable dependency to report what is missing, why it is
    required, how to configure it, and where the integration lives — rather
    than being silently substituted for.
    """
    provider: str
    configured: bool
    missing: list[str] = field(default_factory=list)
    why_required: str = ""
    how_to_enable: str = ""
    implemented_in: str = ""

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "configured": self.configured,
            "missing": list(self.missing),
            "why_required": self.why_required,
            "how_to_enable": self.how_to_enable,
            "implemented_in": self.implemented_in,
        }


@dataclass
class DiscoveryResult:
    """
    What one discovery run produced.

    An empty `records` list with `succeeded=True` means the integration worked
    and the account genuinely holds nothing — a different statement from a
    failure, and the two must not be collapsed.
    """
    succeeded: bool
    records: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""


class DiscoveryAdapter(Protocol):
    provider: str

    def describe(self) -> AdapterDescription: ...

    def discover(self) -> DiscoveryResult: ...
