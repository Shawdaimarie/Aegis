"""Transaction, restart, concurrent-worker and recovery failure regressions."""

import multiprocessing
import sqlite3
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

from aegis.adapters.authorization_store import SQLiteAuthorizationStore, initialize_database
from aegis.core.errors import StateUnavailableError
from aegis.identity.models import ApprovalGrant, DecisionReason, Principal
from aegis.identity.state import ConsumeRequest

NOW = 2_000_000_000


def request(cap="cap-root", rid="request-1", uses=2, approval=False):
    return ConsumeRequest(
        cap,
        uses,
        rid,
        NOW,
        approval,
        "approval-one" if approval else None,
        "sha256:" + "a" * 64,
        NOW + 60,
    )


@pytest.fixture
def ledger(tmp_path):
    path = tmp_path / "authority.sqlite3"
    initialize_database(path)
    return path


def store(path, **kwargs):
    return SQLiteAuthorizationStore(path, clock=lambda: NOW, **kwargs)


def approval():
    return ApprovalGrant(
        approval_id="approval-one",
        capability_id="cap-root",
        tenant="acme",
        approver=Principal(id="human:reviewer", kind="human", tenant="acme"),
        intent_fingerprint="sha256:" + "a" * 64,
        issued_at=NOW,
        expires_at=NOW + 30,
        max_uses=1,
    )


def test_explicit_initialization_never_overwrites_existing_file(ledger, tmp_path):
    before = ledger.read_bytes()
    with pytest.raises(FileExistsError):
        initialize_database(ledger)
    assert ledger.read_bytes() == before
    assert ledger.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="absolute path"):
        initialize_database(Path("relative.sqlite3"))
    with pytest.raises(StateUnavailableError):
        store(tmp_path / "absent.sqlite3")
    with pytest.raises(StateUnavailableError):
        store(Path("relative.sqlite3"))


def test_delegation_budget_and_cascading_revocation_persist(ledger):
    db = store(ledger)
    db.register_capability("root", 3)
    assert (
        db.register_delegation(
            parent_capability_id="root",
            child_capability_id="child",
            reserved_uses=2,
            parent_max_uses=3,
        )
        == 1
    )
    db = store(ledger)
    db.register_delegation(
        parent_capability_id="child",
        child_capability_id="grandchild",
        reserved_uses=1,
        parent_max_uses=2,
    )
    assert db.remaining_uses("root", 3) == 1
    db.revoke("root", "Human stop")
    db = store(ledger)
    for cap, budget in (("root", 3), ("child", 2), ("grandchild", 1)):
        assert db.consume(request(cap, "request-" + cap, budget)).reason == DecisionReason.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        db.register_delegation(
            parent_capability_id="root",
            child_capability_id="late-child",
            reserved_uses=1,
            parent_max_uses=3,
        )


def test_parallel_consumption_never_exceeds_budget(ledger):
    store(ledger).register_capability("cap-root", 2)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(
            pool.map(lambda i: store(ledger).consume(request(rid=f"request-{i}")), range(12))
        )
    assert sum(result.allowed for result in results) == 2
    assert store(ledger).remaining_uses("cap-root", 2) == 0


def worker_consume(arguments):
    path, rid = arguments
    return SQLiteAuthorizationStore(Path(path)).consume(request(rid=rid)).allowed


def test_independent_processes_share_one_budget(ledger):
    store(ledger).register_capability("cap-root", 2)
    with ProcessPoolExecutor(
        max_workers=2, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        results = list(pool.map(worker_consume, [(str(ledger), f"process-{i}") for i in range(6)]))
    assert sum(results) == 2


def test_approval_scope_expiry_and_use_budget_are_enforced(ledger):
    db = store(ledger)
    db.register_capability("cap-root", 2)
    db.store_approval(approval())
    assert db.consume(request(approval=True)).allowed
    assert (
        store(ledger).consume(request(rid="request-2", approval=True)).reason
        == DecisionReason.APPROVAL_INVALID
    )
    assert store(ledger).remaining_uses("cap-root", 2) == 1


@pytest.mark.parametrize("mutation", ["missing", "expired", "mismatch", "corrupt"])
def test_invalid_approval_never_consumes_capability(ledger, mutation):
    db = store(ledger)
    db.register_capability("cap-root", 2)
    if mutation != "missing":
        grant = approval()
        if mutation == "expired":
            grant = grant.model_copy(update={"expires_at": NOW})
        if mutation == "mismatch":
            grant = grant.model_copy(update={"intent_fingerprint": "sha256:" + "b" * 64})
        db.store_approval(grant)
    if mutation == "corrupt":
        with sqlite3.connect(ledger) as connection:
            connection.execute("UPDATE approvals SET body='invalid-json'")
        with pytest.raises(StateUnavailableError):
            db.consume(request(approval=True))
    else:
        assert db.consume(request(approval=True)).reason == DecisionReason.APPROVAL_INVALID
    assert db.remaining_uses("cap-root", 2) == 2


def test_capacity_exhaustion_does_not_evict_replay_history(ledger):
    db = store(ledger, max_request_ids=1)
    db.register_capability("cap-root", 2)
    assert db.consume(request()).allowed
    assert (
        store(ledger, max_request_ids=1).consume(request(rid="another-id")).reason
        == DecisionReason.STATE_UNAVAILABLE
    )
    assert db.consume(request()).reason == DecisionReason.REPLAY_DETECTED
    assert db.remaining_uses("cap-root", 2) == 1


def test_failed_transaction_rolls_back_replay_and_both_budgets(ledger):
    db = store(ledger)
    db.register_capability("cap-root", 2)
    db.store_approval(approval())
    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "CREATE TRIGGER deny_update BEFORE UPDATE ON approvals "
            "BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END"
        )
    with pytest.raises(StateUnavailableError):
        db.consume(request(approval=True))
    assert db.remaining_uses("cap-root", 2) == 2
    with sqlite3.connect(ledger) as connection:
        connection.execute("DROP TRIGGER deny_update")
    assert db.consume(request(approval=True)).allowed


def test_expiry_rechecked_inside_transaction(ledger):
    store(ledger).register_capability("cap-root", 2)
    db = SQLiteAuthorizationStore(ledger, clock=lambda: NOW + 61)
    assert db.consume(request()).reason == DecisionReason.EXPIRED
    assert db.remaining_uses("cap-root", 2) == 2


def test_unregistered_or_inconsistent_budget_is_not_invented(ledger):
    db = store(ledger)
    with pytest.raises(StateUnavailableError):
        db.consume(request())
    db.register_capability("cap-root", 2)
    with pytest.raises(StateUnavailableError):
        db.remaining_uses("cap-root", 3)
    with pytest.raises(StateUnavailableError):
        db.register_capability("cap-root", 10)
    assert db.remaining_uses("cap-root", 2) == 2


def test_symlink_and_corrupt_files_fail_closed(ledger, tmp_path):
    link = tmp_path / "alias.sqlite3"
    link.symlink_to(ledger)
    with pytest.raises(StateUnavailableError):
        store(link)
    ledger.write_bytes(b"not a database")
    with pytest.raises(StateUnavailableError):
        store(ledger)


def test_parallel_delegation_cannot_double_allocate(ledger):
    store(ledger).register_capability("root", 3)

    def delegate(index):
        try:
            store(ledger).register_delegation(
                parent_capability_id="root",
                child_capability_id=f"child-{index}",
                reserved_uses=2,
                parent_max_uses=3,
            )
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(delegate, range(2))) == 1
    assert store(ledger).remaining_uses("root", 3) == 1


def test_consistent_backup_preserves_revocation_and_budget(ledger, tmp_path):
    db = store(ledger)
    db.register_capability("cap-root", 2)
    db.consume(request())
    db.revoke("cap-root", "Owner stop")
    backup = tmp_path / "backup.sqlite3"
    with sqlite3.connect(ledger) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    restored = store(backup)
    assert restored.remaining_uses("cap-root", 2) == 1
    assert restored.consume(request(rid="after-restore")).reason == DecisionReason.REVOKED
