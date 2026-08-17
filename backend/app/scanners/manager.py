import logging
from typing import Dict, Type
from app.scanners.base import Scanner

logger = logging.getLogger(__name__)

class ScannerManager:
    _scanners: Dict[str, Scanner] = {}

    @classmethod
    def register_scanner(cls, scanner: Scanner) -> None:
        """Register an instantiated scanner."""
        if scanner.name in cls._scanners:
            logger.warning(f"Scanner {scanner.name} is already registered. Overwriting.")
        cls._scanners[scanner.name] = scanner
        logger.info(f"Registered scanner: {scanner.name} (v{scanner.version})")

    @classmethod
    def get_scanner(cls, name: str) -> Scanner | None:
        """Retrieve a scanner by name."""
        return cls._scanners.get(name)

    @classmethod
    def get_available_scanners(cls) -> Dict[str, Scanner]:
        """Return only scanners that report is_available() == True."""
        return {name: s for name, s in cls._scanners.items() if s.is_available()}

    @classmethod
    def get_all_scanners(cls) -> Dict[str, Scanner]:
        """Return all registered scanners regardless of availability."""
        return cls._scanners
