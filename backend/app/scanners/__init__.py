from app.scanners.base import Scanner, ScannerResult
from app.scanners.manager import ScannerManager
from app.scanners.nmap import NmapScanner
from app.scanners.nuclei import NucleiScanner
from app.scanners.lynis import LynisScanner
from app.scanners.windows_audit import WindowsAuditScanner

# Auto-register default scanners
ScannerManager.register_scanner(NmapScanner())
ScannerManager.register_scanner(NucleiScanner())
ScannerManager.register_scanner(LynisScanner())
ScannerManager.register_scanner(WindowsAuditScanner())

__all__ = ["Scanner", "ScannerResult", "ScannerManager"]

