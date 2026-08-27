import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.errors import GovernanceViolationError
from aegis.core.types import Checkpoint, RunContext, ScenarioKind, Severity
from aegis.governance.audit import AuditLog
from aegis.governance.boundary import Boundary, Comparator, Predicate
from aegis.governance.engine import PolicyEngine


def halt_boundary() -> Boundary:
    return Boundary(
        id="halt-loss",
        title="t",
        severity=Severity.HALT,
        checkpoints=frozenset({Checkpoint.STEP}),
        predicate=Predicate(path="metrics.loss", op=Comparator.GT, value=100.0),
        owner="o",
        rationale="loss too high",
    )


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        PolicyEngine([halt_boundary(), halt_boundary()], AuditLog())


def test_default_config_blocks_undeclared_dataset(engine):
    ctx = RunContext(run_id="r", scenario=ScenarioKind.INDEPENDENT, tags={"egress": "none"})
    with pytest.raises(GovernanceViolationError) as ei:
        engine.evaluate(Checkpoint.PRE_RUN, ctx)
    assert ei.value.boundary_id == "dataset-hash-required"


def test_advisory_does_not_block(engine):
    ctx = RunContext(
        run_id="r", scenario=ScenarioKind.INDEPENDENT, step=1, resources={"memory_fraction": 0.9}
    )
    d = engine.evaluate(Checkpoint.STEP, ctx)
    assert d.allowed
    assert d.advisories == ("memory-high-watermark",)


def test_halt_precedes_block_and_audit_records_everything(engine, audit):
    ctx = RunContext(
        run_id="r",
        scenario=ScenarioKind.INDEPENDENT,
        step=1,
        metrics={"loss": 1e9},
        resources={"gpu_hours": 1e6},
    )
    d = engine.evaluate(Checkpoint.STEP, ctx, raise_on_block=False)
    assert d.halted_by == "gpu-hours-ceiling"
    assert not d.allowed
    audit.verify()
    assert any(r.decision == "deny" for r in audit)


def test_engine_exposes_no_mutation_surface():
    eng = PolicyEngine([halt_boundary()], AuditLog())
    public = {n for n in dir(eng) if not n.startswith("_")}
    assert public == {"boundaries", "evaluate"}
    assert isinstance(eng.boundaries, tuple)


@settings(max_examples=200)
@given(
    st.dictionaries(
        st.text(min_size=1, max_size=8), st.floats(allow_nan=False, allow_infinity=False)
    ),
    st.dictionaries(st.text(min_size=1, max_size=8), st.text(max_size=8)),
    st.floats(min_value=100.0001, max_value=1e12),
)
def test_no_context_override_disables_halt(metrics, tags, loss):
    """Whatever else is in the context, a crossed HALT boundary always denies."""
    metrics = {**metrics, "loss": loss}
    eng = PolicyEngine([halt_boundary()], AuditLog())
    ctx = RunContext(
        run_id="r", scenario=ScenarioKind.DEPENDENT, step=1, metrics=metrics, tags=tags
    )
    d = eng.evaluate(Checkpoint.STEP, ctx, raise_on_block=False)
    assert d.halted_by == "halt-loss"
    with pytest.raises(GovernanceViolationError):
        eng.evaluate(Checkpoint.STEP, ctx)
