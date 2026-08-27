import pytest
from pydantic import ValidationError

from aegis.core.types import RunContext, ScenarioKind


def test_context_get_resolves_dotted_paths():
    ctx = RunContext(run_id="r1", scenario=ScenarioKind.INDEPENDENT, metrics={"loss": 0.5}, step=3)
    assert ctx.get("metrics.loss") == 0.5
    assert ctx.get("metrics.missing") is None
    assert ctx.get("step") == 3
    assert ctx.get("nonexistent.x") is None


def test_context_rejects_unknown_fields_and_is_frozen():
    with pytest.raises(ValidationError):
        RunContext(run_id="r", scenario=ScenarioKind.INDEPENDENT, extra=1)
    ctx = RunContext(run_id="r", scenario=ScenarioKind.INDEPENDENT)
    with pytest.raises(ValidationError):
        ctx.step = 5
