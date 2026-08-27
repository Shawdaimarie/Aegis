import pytest

from aegis.core.errors import IntegrityError
from aegis.governance.audit import GENESIS, AuditLog


def test_chain_links_and_verifies(audit: AuditLog):
    r0 = audit.append("a", "act", "res", "ok")
    r1 = audit.append("a", "act", "res", "ok")
    assert r0.prev == GENESIS
    assert r1.prev == r0.id
    audit.verify()


def test_tampering_is_detected(audit: AuditLog):
    audit.append("a", "act", "res", "ok")
    audit.append("a", "act", "res", "ok")
    audit._records[0] = audit._records[0].model_copy(update={"decision": "forged"})
    with pytest.raises(IntegrityError):
        audit.verify()


def test_reordering_is_detected(audit: AuditLog):
    audit.append("a", "x", "r", "ok")
    audit.append("a", "y", "r", "ok")
    audit._records.reverse()
    with pytest.raises(IntegrityError):
        audit.verify()
