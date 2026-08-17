from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

@dataclass
class ScannerResult:
    target: str
    scanner_name: str
    findings: list[dict[str, Any]]
    raw_data: Any = None
    hosts_discovered: int = 0
    findings_generated: int = 0

class Scanner(ABC):
    """
    Base interface for all security scanners in the Omni Cyber Guard platform.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g., 'nmap', 'nuclei')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Version of the scanner integration."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the underlying tool is installed and available."""
        pass

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate if the target is acceptable for this scanner."""
        pass

    @abstractmethod
    def execute(self, target: str, progress_callback: Callable[[str], None] = None, **kwargs) -> ScannerResult:
        """
        Execute the scan against the target.
        Must return a normalized ScannerResult.
        """
        pass
