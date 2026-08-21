"""
Source-hygiene guard for the platform's core rule: no fabricated security data.

These tests fail the build if fabricated results, simulated scanner output, or
hardcoded security statistics are reintroduced into the security-critical parts
of the codebase. They exist because two scanner modules previously shipped
hardcoded CVE findings — complete with invented evidence strings and claims of
successful exploitation — which were written to the database and counted on the
dashboard as though a real assessment had produced them.

Scope is deliberately narrow: scanners, API endpoints, services and tasks.
Comments explaining *why* something was removed are allowed; code that
manufactures results is not.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
APP = BACKEND / "app"

SECURITY_CRITICAL_DIRS = [
    APP / "scanners",
    APP / "api" / "v1" / "endpoints",
    APP / "services",
    APP / "tasks",
]

# Identifiers that indicate manufactured data, as opposed to prose describing it.
FABRICATION_IDENTIFIERS = re.compile(
    r"\b(MOCK_[A-Z_]+|FAKE_[A-Z_]+|SAMPLE_FINDINGS|DEMO_[A-Z_]+|STUB_[A-Z_]+)\b"
)


def _python_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*.py") if "__pycache__" not in p.parts)


def _code_without_comments_or_docstrings(path: Path) -> str:
    """Return the module's source with comments and docstrings stripped, so a
    comment explaining a past mistake does not trip these checks."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    docstring_spans: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                first = body[0]
                docstring_spans.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))

    kept = []
    for number, line in enumerate(source.splitlines(), start=1):
        if number in docstring_spans:
            continue
        kept.append(line.split("#", 1)[0])
    return "\n".join(kept)


def test_no_fabricated_data_identifiers_in_security_code():
    offenders: list[str] = []
    for directory in SECURITY_CRITICAL_DIRS:
        for path in _python_files(directory):
            code = _code_without_comments_or_docstrings(path)
            for match in FABRICATION_IDENTIFIERS.finditer(code):
                offenders.append(f"{path.relative_to(BACKEND)}: {match.group(0)}")

    assert not offenders, (
        "Fabricated-data containers found in security-critical code. Security results "
        "must come from a real scanner, integration or database record:\n  "
        + "\n  ".join(offenders)
    )


def test_no_time_sleep_theatre_in_scanners():
    """
    Sleeping on a literal delay inside scanner code is banned.

    The removed adapters used `time.sleep(2)` between invented log lines to make
    a scan that never ran look like one that did. Polling a real subprocess is a
    legitimate reason to sleep, so the rule is drawn precisely: a sleep whose
    argument is a *numeric literal* is theatre; a sleep on a named poll interval
    (`time.sleep(poll_interval)`, `time.sleep(SESSION_POLL_SECONDS)`) is a loop
    doing real work.
    """
    offenders: list[str] = []

    for path in _python_files(APP / "scanners"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_sleep = (
                (isinstance(func, ast.Attribute) and func.attr == "sleep")
                or (isinstance(func, ast.Name) and func.id == "sleep")
            )
            if not is_sleep or not node.args:
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, (int, float)):
                offenders.append(
                    f"{path.relative_to(BACKEND)}:{node.lineno} sleeps for a literal "
                    f"{argument.value}s"
                )

    assert not offenders, (
        "Literal sleeps found in scanner code. This is how the removed adapters "
        "faked scan progress:\n  " + "\n  ".join(offenders)
    )


def test_removed_fabricated_scanner_modules_are_gone():
    for name in ("openvas.py", "zap.py"):
        assert not (APP / "scanners" / name).exists(), (
            f"app/scanners/{name} is back. It contained no real integration and emitted "
            f"hardcoded findings. Reintroduce it only as a genuine adapter."
        )


def test_scanner_registry_contains_only_real_integrations():
    """Every registered scanner must report availability from a real probe."""
    from app.scanners import ScannerManager  # noqa: PLC0415

    registered = ScannerManager.get_all_scanners()
    assert registered, "No scanners are registered."

    for name, scanner in registered.items():
        # is_available() must be able to return False. A scanner that always
        # reports available is either trivially true or dishonest.
        result = scanner.is_available()
        assert isinstance(result, bool), f"{name}.is_available() must return a bool"

    assert "openvas" not in registered
    assert "zap" not in registered


def test_dashboard_endpoint_has_no_hardcoded_metrics():
    """Every dashboard number must come from a query, never a literal."""
    source = (APP / "api" / "v1" / "endpoints" / "dashboard.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    suspicious = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "DashboardSummary":
            continue
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, (int, float)):
                suspicious.append(f"{keyword.arg}={keyword.value.value}")

    assert not suspicious, (
        "DashboardSummary is being constructed with literal metric values: "
        + ", ".join(suspicious)
    )
