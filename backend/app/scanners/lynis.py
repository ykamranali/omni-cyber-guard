import os
import shutil
import subprocess
import tempfile
from typing import Any

from app.scanners.base import Scanner, ScannerResult

class LynisScanner(Scanner):
    @property
    def name(self) -> str:
        return "lynis"

    @property
    def version(self) -> str:
        return "3.0.0"

    def is_available(self) -> bool:
        # Check if the Lynis binary is installed locally
        return shutil.which("lynis") is not None

    def validate_target(self, target: str) -> bool:
        # Lynis is primarily for local audits or remote SSH.
        # For remote execution, we would expect an SSH connection string or IP.
        # Here we do basic validation, assuming IP/hostname.
        if not target:
            return False
        return True

    def execute(self, target: str, **kwargs) -> ScannerResult:
        if not self.is_available():
            raise RuntimeError("The 'lynis' binary is not installed in this environment.")
        
        # In a real environment, for remote hosts, you would use SSH: 
        # lynis audit system --remote <target>
        # For this milestone, we wrap the local execution or simulated remote execution.
        
        # We run lynis and output to a temporary log file to parse findings
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = os.path.join(tmp_dir, "lynis-report.dat")
            cmd = [
                "lynis",
                "audit",
                "system",
                "--quick",
                "--report-file", report_file
            ]
            
            # Note: For real remote scanning, we'd wrap this with SSH if authorized.
            # cmd = ["ssh", target, "lynis", "audit", "system", "--quick"]
            
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"Lynis scan of {target} timed out.") from exc
            
            if proc.returncode not in (0, 1, 2) and not os.path.exists(report_file):
                raise RuntimeError(f"Lynis scan failed (exit {proc.returncode}): {proc.stderr.strip()[:2000]}")
            
            findings = []
            if os.path.exists(report_file):
                findings = self._parse_report_file(report_file)
                        
            return ScannerResult(
                target=target,
                scanner_name=self.name,
                findings=findings,
                findings_generated=len(findings)
            )

    def _parse_report_file(self, file_path: str) -> list[dict[str, Any]]:
        """Parse the standard Lynis .dat report format into Findings."""
        findings = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("warning[]") or line.startswith("suggestion[]"):
                    # Format: warning[]=TEST-ID|message|details|
                    parts = line.split("=")
                    if len(parts) > 1:
                        data_parts = parts[1].split("|")
                        if len(data_parts) >= 2:
                            test_id = data_parts[0]
                            message = data_parts[1]
                            
                            severity = "MEDIUM"
                            if line.startswith("warning"):
                                severity = "HIGH"
                                
                            findings.append({
                                "title": f"Lynis: {test_id}",
                                "description": message,
                                "severity": severity,
                                "evidence": f"Failed Lynis compliance check: {test_id}",
                                "remediation_guidance": "Review Lynis documentation for this test ID to harden the system configuration.",
                                "source": self.name,
                            })
        return findings
