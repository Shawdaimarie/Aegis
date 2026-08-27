import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from aegis.core.types import Checkpoint, RunContext, ScenarioKind, Severity
from aegis.governance.boundary import Boundary, Comparator, Predicate


def ctx(**metrics: float) -> RunContext:
    return RunContext(run_id="r", scenario=ScenarioKind.INDEPENDENT, metrics=metrics)


@pytest.mark.parametrize(
    ("op", "value", "actual", "expected"),
    [
        (Comparator.GT, 1.0, 2.0, True),
        (Comparator.GT, 1.0, 1.0, False),
        (Comparator.GE, 1.0, 1.0, True),
        (Comparator.LT, 1.0, 0.5, True),
        (Comparator.LE, 1.0, 1.0, True),
        (Comparator.EQ, 1.0, 1.0, True),
        (Comparator.NE, 1.0, 1.0, False),
    ],
)
def test_comparators(op, value, actual, expected):
    assert Predicate(path="metrics.x", op=op, value=value).holds(ctx(x=actual)) is expected


def test_missing_and_present():
    assert Predicate(path="metrics.x", op=Comparator.MISSING).holds(ctx())
    assert not Predicate(path="metrics.x", op=Comparator.PRESENT).holds(ctx())
    assert Predicate(path="metrics.x", op=Comparator.GT, value=0).holds(ctx()) is False


@given(
    st.floats(allow_nan=False, allow_infinity=False),
    st.floats(allow_nan=False, allow_infinity=False),
)
def test_gt_and_le_are_complementary(threshold, actual):
    gt = Predicate(path="metrics.x", op=Comparator.GT, value=threshold).holds(ctx(x=actual))
    le = Predicate(path="metrics.x", op=Comparator.LE, value=threshold).holds(ctx(x=actual))
    assert gt != le


def test_boundary_id_must_be_kebab_case():
    with pytest.raises(ValidationError):
        Boundary(
            id="Bad_ID",
            title="t",
            severity=Severity.HALT,
            checkpoints=frozenset({Checkpoint.STEP}),
            predicate=Predicate(path="step", op=Comparator.GT, value=1),
            owner="o",
            rationale="r",
        )


def test_numeric_ops_coerce_and_require_value():
    p = Predicate(path="metrics.x", op=Comparator.GT, value="10")
    assert p.value == 10.0
    with pytest.raises(ValidationError):
        Predicate(path="metrics.x", op=Comparator.GT)
    assert not Predicate(path="tags.t", op=Comparator.GT, value=1).holds(
        RunContext(run_id="r", scenario=ScenarioKind.INDEPENDENT, tags={"t": "s"})
    )
