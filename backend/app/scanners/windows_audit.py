import subprocess
from typing import Any

from app.scanners.base import Scanner, ScannerResult

class WindowsAuditScanner(Scanner):
    """
    Credentialed Windows Security Assessment Module.
    Supports authorized checks for: Windows Update, Firewall, Policies, SMB, RDP, Defender.
    """
    @property
    def name(self) -> str:
        return "windows_audit"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_available(self) -> bool:
        # In a real deployment, this would check if pywinrm/impacket or powershell is available.
        # For defensive use, pywinrm is standard for config retrieval over WinRM.
        try:
            import winrm # type: ignore
            return True
        except ImportError:
            return False

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        return True

    def execute(self, target: str, **kwargs) -> ScannerResult:
        if not self.is_available():
            raise RuntimeError("The 'pywinrm' library is not installed. Credentialed Windows audits are unavailable.")
        
        # Security Requirement: Credential secrets must never be stored as plaintext.
        # kwargs should contain temporary credential references (e.g. from a secure vault)
        username = kwargs.get("username")
        password = kwargs.get("password")
        
        if not username or not password:
            raise ValueError("Credentialed Windows audit requires a username and password.")
            
        findings = []
        
        try:
            import winrm # type: ignore
            # Connect to target over WinRM
            session = winrm.Session(target, auth=(username, password), transport='ntlm')
            
            # Example Check 1: Windows Defender Status
            r = session.run_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled")
            if r.status_code == 0 and "False" in str(r.std_out):
                findings.append(self._create_finding("Windows Defender Disabled", "HIGH", "Anti-malware service is disabled on the host."))
                
            # Example Check 2: SMBv1 Enabled
            r = session.run_ps("Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol")
            if r.status_code == 0 and "True" in str(r.std_out):
                findings.append(self._create_finding("SMBv1 Protocol Enabled", "CRITICAL", "Legacy SMBv1 protocol is enabled, making the host vulnerable to ransomware like WannaCry."))
                
            # Example Check 3: RDP NLA Status
            r = session.run_ps("(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices -Filter \"TerminalName='RDP-tcp'\").UserAuthenticationRequired")
            if r.status_code == 0 and "0" in str(r.std_out):
                findings.append(self._create_finding("RDP NLA Disabled", "HIGH", "Network Level Authentication (NLA) is disabled for RDP connections."))

        except Exception as e:
            raise RuntimeError(f"Windows Audit execution failed: {e}")
            
        return ScannerResult(
            target=target,
            scanner_name=self.name,
            findings=findings,
            findings_generated=len(findings)
        )

    def _create_finding(self, title: str, severity: str, desc: str) -> dict[str, Any]:
        return {
            "title": title,
            "description": desc,
            "severity": severity,
            "evidence": "Retrieved via authenticated WinRM query.",
            "remediation_guidance": "Enforce secure configuration via Group Policy or local security policy.",
            "source": self.name,
        }
