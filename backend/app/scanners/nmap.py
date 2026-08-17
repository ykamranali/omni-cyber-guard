from typing import Callable
from app.scanners.base import Scanner, ScannerResult
from app.services.network_scanner import (
    run_discovery_and_service_scan,
    nmap_available,
    validate_authorized_target,
    ScanAuthorizationError
)

class NmapScanner(Scanner):
    @property
    def name(self) -> str:
        return "nmap"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_available(self) -> bool:
        return nmap_available()

    def validate_target(self, target: str) -> bool:
        try:
            validate_authorized_target(target)
            return True
        except ScanAuthorizationError:
            return False

    def execute(self, target: str, progress_callback: Callable = None, **kwargs) -> ScannerResult:
        if not self.is_available():
            raise RuntimeError("nmap is not available.")
        
        # We wrap the existing logic. Findings and assets are generated inside scan_tasks,
        # but to adhere to the interface, we can return the raw hosts here.
        # Alternatively, the ScannerResult can hold the parsed data.
        
        hosts = run_discovery_and_service_scan(target, progress_callback=progress_callback)
        
        # We return the hosts in raw_data, so the caller (scan_tasks) can process them.
        return ScannerResult(
            target=target,
            scanner_name=self.name,
            findings=[], # findings will be parsed by scan_tasks for now
            raw_data=hosts,
            hosts_discovered=len(hosts)
        )
