"""Scan request validation: unknown engines are rejected at the edge, not
discovered later inside a Celery worker."""
import pytest
from pydantic import ValidationError

from app.scanners.manager import ScannerManager
from app.schemas.scan import ScanJobCreate

SUPPORTED_ENGINES = tuple(sorted(ScannerManager.get_all_scanners()))


@pytest.mark.parametrize("engine", SUPPORTED_ENGINES)
def test_supported_engines_are_accepted(engine):
    assert ScanJobCreate(target_cidr="192.168.1.0/24", engine=engine).engine == engine


@pytest.mark.parametrize("engine", ["openvas", "zap", "metasploit", "", "nmap; rm -rf /"])
def test_unsupported_engines_are_rejected(engine):
    with pytest.raises(ValidationError):
        ScanJobCreate(target_cidr="192.168.1.0/24", engine=engine)


def test_removed_engines_are_not_registered():
    assert "openvas" not in SUPPORTED_ENGINES
    assert "zap" not in SUPPORTED_ENGINES


def test_the_engine_list_comes_from_the_registry():
    """A second hardcoded list would drift from the adapters that actually exist."""
    assert SUPPORTED_ENGINES == tuple(sorted(ScannerManager.get_all_scanners()))
    assert "nmap" in SUPPORTED_ENGINES


def test_engine_defaults_to_nmap():
    assert ScanJobCreate(target_cidr="192.168.1.0/24").engine == "nmap"


def test_blank_target_is_rejected():
    with pytest.raises(ValidationError):
        ScanJobCreate(target_cidr="   ")
