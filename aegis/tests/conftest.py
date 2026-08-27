from pathlib import Path

import pytest

from aegis.governance.audit import AuditLog
from aegis.governance.engine import PolicyEngine
from aegis.governance.loader import load_boundaries

ROOT = Path(__file__).resolve().parents[1]
GOV = ROOT / "configs/governance/default.yaml"


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def engine(audit: AuditLog) -> PolicyEngine:
    return PolicyEngine(load_boundaries(GOV), audit)
