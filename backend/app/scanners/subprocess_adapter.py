"""
Base class for adapters that drive a local command-line tool.

`subprocess.Popen` is genuinely asynchronous, so `start_scan` really does start
and return — the session model is not a pretence layered over a blocking call.
Output is drained on a reader thread so a chatty tool cannot deadlock on a full
pipe, and cancellation terminates the actual process rather than marking a row.

Subclasses supply three things: the command to run, how to read the output, and
how to normalize it.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.scanners.contract import (
    ConfigurationStatus, ProgressCallback, ScanProgress, ScanRequest, ScanSession,
    ScannerAdapter, ScannerResult, SessionState,
)

logger = logging.getLogger(__name__)

TERMINATE_GRACE_SECONDS = 10
KILL_GRACE_SECONDS = 5


@dataclass
class SubprocessContext:
    """Adapter-owned state for one running command."""

    process: subprocess.Popen
    request: ScanRequest
    output_lines: list[str] = field(default_factory=list)
    reader: threading.Thread | None = None
    canceled: bool = False
    started_at: float = field(default_factory=time.monotonic)
    #: Populated by the subclass when the command finishes.
    artifacts: dict[str, Any] = field(default_factory=dict)

    @property
    def output(self) -> str:
        return "\n".join(self.output_lines)


class SubprocessScannerAdapter(ScannerAdapter):
    """Common machinery for tools invoked as a child process."""

    #: Binary that must be on PATH for this adapter to work.
    binary: str = ""
    #: Shown to the operator when the binary is missing.
    install_hint: str = ""

    # --- configuration ----------------------------------------------------

    def validate_configuration(self) -> ConfigurationStatus:
        path = shutil.which(self.binary) if self.binary else None
        if path is None:
            return ConfigurationStatus.not_configured(
                summary=f"The '{self.binary}' binary was not found on this worker.",
                remediation=self.install_hint or f"Install {self.binary} on the scan worker.",
            )
        return ConfigurationStatus.ready(
            summary=f"{self.binary} found at {path}.",
            tool_version=self._detect_tool_version(),
        )

    def _detect_tool_version(self) -> str | None:
        """Best-effort version probe. Returns None rather than guessing."""
        if not self.binary:
            return None
        try:
            completed = subprocess.run(
                [self.binary, "--version"], capture_output=True, text=True, timeout=10, check=False
            )
            first_line = (completed.stdout or completed.stderr or "").strip().splitlines()
            return first_line[0][:120] if first_line else None
        except Exception:
            return None

    # --- subclass hooks ---------------------------------------------------

    def build_command(self, request: ScanRequest, context_dir: str) -> list[str]:
        """Return the argv for this scan. Never interpolate raw user input."""
        raise NotImplementedError

    def is_progress_line(self, line: str) -> bool:
        """Whether a line is worth forwarding to the live scan log."""
        return True

    def preflight_notes(self, request: ScanRequest) -> list[str]:
        """
        Observations about the environment to record before the tool starts.

        These go to the top of the operator-visible scan log and into the stored
        output, so a result that is thin because of where the worker sits is
        explained in the same place the result is read. Returning nothing means
        nothing was found worth saying — never a silent degradation.
        """
        return []

    def collect_results(self, context: SubprocessContext) -> ScannerResult:
        """Parse whatever the finished command produced."""
        raise NotImplementedError

    def acceptable_exit_codes(self) -> tuple[int, ...]:
        return (0,)

    # --- execution --------------------------------------------------------

    def start_scan(self, request: ScanRequest, on_output: ProgressCallback | None = None) -> ScanSession:
        status = self.validate_configuration()
        if not status.available:
            raise RuntimeError(f"{status.summary} {status.remediation}".strip())

        validation = self.validate_target(request.target)
        if not validation.valid:
            raise ValueError(validation.reason)

        target = validation.normalized_target or request.target
        request = ScanRequest(
            target=target,
            credential=request.credential,
            options=request.options,
            timeout_seconds=request.timeout_seconds,
        )

        import tempfile

        # Computed before anything is launched, so it is recorded even if the
        # process fails to start.
        try:
            notes = self.preflight_notes(request)
        except Exception:
            logger.exception("scanner %s: preflight check failed", self.name)
            notes = []

        workdir = tempfile.mkdtemp(prefix=f"ocg-{self.name}-")
        command = self.build_command(request, workdir)

        logger.info("scanner %s: starting %s", self.name, " ".join(command[:4]))
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        context = SubprocessContext(process=process, request=request)
        context.artifacts["workdir"] = workdir

        for note in notes:
            context.output_lines.append(note)
            if on_output:
                on_output(note)

        def drain() -> None:
            # Draining on a thread keeps a chatty tool from blocking on a full
            # stdout pipe while the orchestrator is between polls.
            try:
                for line in process.stdout:  # type: ignore[union-attr]
                    stripped = line.rstrip("\n")
                    context.output_lines.append(stripped)
                    if on_output and self.is_progress_line(stripped):
                        on_output(stripped)
            except Exception:
                logger.exception("scanner %s: output reader failed", self.name)
            finally:
                try:
                    process.stdout.close()  # type: ignore[union-attr]
                except Exception:
                    pass

        context.reader = threading.Thread(target=drain, daemon=True, name=f"ocg-{self.name}-reader")
        context.reader.start()

        return ScanSession.new(adapter=self.name, target=target, context=context)

    def get_status(self, session: ScanSession) -> ScanProgress:
        context: SubprocessContext = session.context
        process = context.process
        code = process.poll()

        if code is None:
            if time.monotonic() - context.started_at > context.request.timeout_seconds:
                self.cancel_scan(session)
                return ScanProgress(
                    state=SessionState.FAILED,
                    error=(
                        f"{self.name} exceeded its {context.request.timeout_seconds}s budget "
                        f"and was terminated."
                    ),
                )
            return ScanProgress(
                state=SessionState.RUNNING,
                # Most CLI tools do not report completion percentage. Reporting
                # "unknown" is honest; a synthetic progress bar is not.
                percent_complete=None,
                message=context.output_lines[-1] if context.output_lines else "",
            )

        if context.canceled:
            return ScanProgress(state=SessionState.CANCELED, message="Cancelled by an operator.")

        if code in self.acceptable_exit_codes():
            return ScanProgress(state=SessionState.COMPLETED, percent_complete=100.0)

        tail = "\n".join(context.output_lines[-20:])
        return ScanProgress(
            state=SessionState.FAILED,
            error=f"{self.name} exited with code {code}.\n{tail}"[:4000],
        )

    def get_results(self, session: ScanSession) -> ScannerResult:
        progress = self.get_status(session)
        if not progress.finished:
            raise RuntimeError(
                f"{self.name} scan of {session.target} is still running; results are not available yet."
            )

        context: SubprocessContext = session.context
        if context.reader is not None:
            context.reader.join(timeout=5)

        try:
            if progress.state is SessionState.COMPLETED:
                return self.collect_results(context)
            return ScannerResult(
                target=session.target,
                scanner_name=self.name,
                error=progress.error or "Scan did not complete.",
            )
        finally:
            self._cleanup(context)

    def cancel_scan(self, session: ScanSession) -> bool:
        context: SubprocessContext = session.context
        process = context.process
        if process.poll() is not None:
            return False

        context.canceled = True
        process.terminate()
        try:
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                logger.error("scanner %s: process %s ignored SIGKILL", self.name, process.pid)
                return False
        return True

    # --- helpers ----------------------------------------------------------

    def _cleanup(self, context: SubprocessContext) -> None:
        import shutil as _shutil

        workdir = context.artifacts.get("workdir")
        if workdir:
            _shutil.rmtree(workdir, ignore_errors=True)

    def run_to_completion(
        self, request: ScanRequest, on_output: ProgressCallback | None = None,
        cancel_check=None, poll_interval: float = 0.5,
    ) -> ScannerResult:
        """
        Convenience for callers that want a blocking scan with cancellation.

        Kept alongside the session API rather than replacing it: the session API
        is what a future scheduler or a remote adapter needs, and this wrapper
        is what the current Celery task uses.
        """
        session = self.start_scan(request, on_output=on_output)
        while True:
            progress = self.get_status(session)
            if progress.finished:
                break
            if cancel_check is not None and cancel_check():
                self.cancel_scan(session)
                break
            time.sleep(poll_interval)
        return self.get_results(session)
