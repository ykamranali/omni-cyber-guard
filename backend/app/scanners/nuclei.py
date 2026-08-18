import json
import shutil
import subprocess
import tempfile
from typing import Any

from app.scanners.base import Scanner, ScannerResult

class NucleiScanner(Scanner):
    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def version(self) -> str:
        return "3.0.0"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def validate_target(self, target: str) -> bool:
        # Nuclei can scan URLs, IPs, etc. We would enforce scope here.
        # For simplicity in this milestone, we will assume it's validated by the orchestrator.
        if target.startswith("http") or len(target.split(".")) == 4:
            return True
        return False

    def execute(self, target: str, progress_callback: Any = None, **kwargs) -> ScannerResult:
        if not self.is_available():
            raise RuntimeError("The 'nuclei' binary is not installed in this environment.")
        
        findings = []
        if progress_callback:
            progress_callback(f"Initializing Nuclei vulnerability scan against {target}...\n")
            progress_callback("This may take several minutes depending on the target scope.\n\n")

        with tempfile.NamedTemporaryFile(suffix=".json") as tmp_file:
            cmd = [
                "nuclei",
                "-target", target,
                "-json-export", tmp_file.name
            ]
            
            try:
                # We use Popen to stream the output for the progress callback
                proc = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT, 
                    text=True,
                    bufsize=1
                )
                
                # Stream the terminal output
                for line in iter(proc.stdout.readline, ''):
                    if progress_callback and line.strip():
                        progress_callback(line)
                
                proc.stdout.close()
                return_code = proc.wait(timeout=600)
                
                if return_code != 0 and not tmp_file.read():
                    raise RuntimeError(f"Nuclei scan failed (exit {return_code})")
                
            except subprocess.TimeoutExpired as exc:
                if 'proc' in locals():
                    proc.kill()
                raise RuntimeError(f"Nuclei scan of {target} timed out.") from exc
            
            if progress_callback:
                progress_callback("\nNuclei scan completed. Parsing vulnerability report...\n")

            # Read results
            tmp_file.seek(0)
            lines = tmp_file.readlines()
            for line in lines:
                if line.strip():
                    try:
                        data = json.loads(line)
                        findings.append(self.normalize_result(data))
                    except Exception:
                        pass
                        
            return ScannerResult(
                target=target,
                scanner_name=self.name,
                findings=findings,
                findings_generated=len(findings)
            )

    def normalize_result(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Convert Nuclei JSON structure to our internal finding structure."""
        info = raw_data.get("info", {})
        return {
            "title": info.get("name", "Unknown Nuclei Finding"),
            "description": info.get("description", "No description provided."),
            "severity": info.get("severity", "info").upper(),
            "evidence": raw_data.get("matched-at", ""),
            "remediation_guidance": info.get("remediation", "See Nuclei template details."),
            "source": self.name,
        }
