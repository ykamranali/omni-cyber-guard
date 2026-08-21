"""
External vulnerability intelligence synchronisation.

Each feed is split into a fetcher and a parser. The parser is a pure function
over the payload, which is what makes it testable against real captured
responses without a network; the fetcher deals with HTTP, pagination and rate
limits.

Common rules across all three feeds:

* Nothing is invented. A field the feed does not provide stays empty.
* A failed sync is recorded as failed. It never leaves a stale success
  timestamp behind, because "last synced 4 hours ago" and "last *attempted* 4
  hours ago and failed" lead to very different decisions.
* Synchronisation is incremental where the feed supports it, so a routine
  refresh does not re-download the entire catalogue.
"""
from app.services.intel.cpe import CpeName, cpe_matches_software, parse_cpe
from app.services.intel.versions import compare_versions, version_in_range

__all__ = [
    "CpeName",
    "parse_cpe",
    "cpe_matches_software",
    "compare_versions",
    "version_in_range",
]
