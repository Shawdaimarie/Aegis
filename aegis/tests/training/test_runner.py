import pytest

from aegis.core.errors import ConfigurationError, GovernanceViolationError
from aegis.core.types import ScenarioKind
from aegis.training.runner import Runner, RunSpec
from aegis.training.scenarios import DependencyEdge, DependencyGraph

H = "sha256:" + "a" * 64


def spec(**kw) -> RunSpec:
    base = {
        "run_id": "run-1",
        "scenario": ScenarioKind.INDEPENDENT,
        "root_seed": 1,
        "steps": 10,
        "dataset_hash": H,
        "git_commit": "deadbeef",
        "config_hash": "c",
        "env_lock_hash": "e",
    }
    return RunSpec(**{**base, **kw})


def converging(i, _):
    return {"loss": 2.0 * 0.9**i, "res:gpu_hours": 0.01 * i}


def test_completed_run_emits_manifest(engine):
    m = Runner(engine).run(spec(), converging)
    assert m.governance_decisions[0] == "pre_run:allow"
    assert m.governance_decisions[-1] == "post_run:allow"
    assert m.audit_head
    assert m.final_metrics["loss"] < 2.0


def test_same_seed_same_manifest_id(engine):
    a = Runner(engine).run(spec(), converging)
    b = Runner(engine).run(spec(), converging)
    assert a.model_dump(exclude={"started_at", "finished_at", "audit_head"}) == b.model_dump(
        exclude={"started_at", "finished_at", "audit_head"}
    )


def test_halt_stops_run_and_attaches_manifest(engine):
    def diverging(i, _):
        return {"loss": 10.0**i, "res:gpu_hours": 0.0}

    with pytest.raises(GovernanceViolationError) as ei:
        Runner(engine).run(spec(steps=20), diverging)
    assert ei.value.boundary_id == "loss-divergence"
    assert "halt:loss-divergence" in ei.value.manifest.governance_decisions


def test_scenario_consistency_enforced(engine):
    with pytest.raises(ConfigurationError):
        Runner(engine).run(spec(scenario=ScenarioKind.DEPENDENT), converging)
    g = DependencyGraph(
        edges=(DependencyEdge(source="b", target="run-1", kind="adapter", source_version="1"),)
    )
    with pytest.raises(ConfigurationError):
        Runner(engine).run(spec(dependencies=g), converging)
    m = Runner(engine).run(spec(scenario=ScenarioKind.DEPENDENT, dependencies=g), converging)
    assert m.dependencies is not None


def test_spec_requires_scenario():
    with pytest.raises(Exception, match="scenario"):
        RunSpec(
            run_id="r-1",
            root_seed=1,
            steps=1,
            dataset_hash=H,
            git_commit="deadbeef",
            config_hash="c",
            env_lock_hash="e",
        )


def test_manifest_id_is_seed_deterministic(engine):
    a = Runner(engine).run(spec(), converging)
    b = Runner(engine).run(spec(), converging)
    c = Runner(engine).run(spec(root_seed=2), converging)
    assert a.manifest_id == b.manifest_id != c.manifest_id
