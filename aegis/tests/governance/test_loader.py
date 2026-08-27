from pathlib import Path

import pytest

from aegis.core.errors import ConfigurationError
from aegis.governance.loader import load_boundaries
from tests.conftest import GOV


def test_default_file_loads_and_contains_halt():
    bs = load_boundaries(GOV)
    assert {b.id for b in bs} >= {"gpu-hours-ceiling", "dataset-hash-required"}


def test_unknown_keys_rejected(tmp_path: Path):
    f = tmp_path / "g.yaml"
    f.write_text("version: 1\nboundaries: []\nextra: 1\n")
    with pytest.raises(ConfigurationError):
        load_boundaries(f)


def test_missing_file(tmp_path: Path):
    with pytest.raises(ConfigurationError):
        load_boundaries(tmp_path / "nope.yaml")


def test_bad_yaml(tmp_path: Path):
    f = tmp_path / "g.yaml"
    f.write_text("version: [unclosed")
    with pytest.raises(ConfigurationError):
        load_boundaries(f)
