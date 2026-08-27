"""Governed run loop. The only sanctioned way to execute a training scenario."""

from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.errors import ConfigurationError, GovernanceViolationError
from aegis.core.seeding import Seeder
from aegis.core.types import Checkpoint, RunContext, ScenarioKind
from aegis.governance.engine import PolicyEngine
from aegis.training.manifest import TrainingManifest
from aegis.training.scenarios import DependencyGraph

StepFn = Callable[[int, Seeder], dict[str, float]]
"""A training step: given step index and seeder, return metrics/resources for that step."""


class RunSpec(BaseModel):
    """Validated inputs for one run. ``scenario`` has no default by design."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    scenario: ScenarioKind
    root_seed: int = Field(ge=0)
    steps: int = Field(ge=1, le=10_000_000)
    governance_cadence: int = Field(ge=1, default=1)
    dataset_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    egress: str = Field(pattern=r"^(none|allowlist:[a-z0-9.,-]+)$", default="none")
    git_commit: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    config_hash: str
    env_lock_hash: str
    dependencies: DependencyGraph | None = None

    def validate_scenario(self) -> None:
        """Enforce scenario/dependency consistency.

        Raises:
            ConfigurationError: Independent run declares dependencies, or dependent run omits them.
        """
        if self.scenario is ScenarioKind.INDEPENDENT and self.dependencies is not None:
            raise ConfigurationError("independent scenario must not declare dependencies")
        if self.scenario is ScenarioKind.DEPENDENT and (
            self.dependencies is None or not self.dependencies.edges
        ):
            raise ConfigurationError("dependent scenario must declare at least one dependency")


class Runner:
    """Executes a RunSpec under a PolicyEngine and emits a TrainingManifest."""

    def __init__(self, engine: PolicyEngine) -> None:
        """Bind a policy engine."""
        self._engine = engine

    def run(self, spec: RunSpec, step_fn: StepFn) -> TrainingManifest:
        """Execute the run.

        Governance is evaluated pre-run, every ``governance_cadence`` steps, and post-run.
        A HALT stops the loop and the manifest records the halting boundary; the
        GovernanceViolationError is then re-raised so callers cannot ignore it.

        Raises:
            ConfigurationError: Spec inconsistent.
            GovernanceViolationError: A BLOCKING or HALT boundary fired.
        """
        spec.validate_scenario()
        seeder = Seeder(spec.root_seed)
        decisions: list[str] = []
        tags = {"dataset_hash": spec.dataset_hash, "egress": spec.egress}

        ctx = RunContext(run_id=spec.run_id, scenario=spec.scenario, tags=tags)
        d = self._engine.evaluate(Checkpoint.PRE_RUN, ctx)
        decisions.append(f"{d.checkpoint}:allow")

        metrics: dict[str, float] = {}
        resources: dict[str, float] = {}
        halted_by: str | None = None
        try:
            for step in range(1, spec.steps + 1):
                out = step_fn(step, seeder)
                for k, v in out.items():
                    (resources if k.startswith("res:") else metrics)[k.removeprefix("res:")] = v
                if step % spec.governance_cadence == 0 or step == spec.steps:
                    ctx = RunContext(
                        run_id=spec.run_id,
                        scenario=spec.scenario,
                        step=step,
                        metrics=metrics,
                        resources=resources,
                        tags=tags,
                    )
                    d = self._engine.evaluate(Checkpoint.STEP, ctx)
                    if d.advisories:
                        decisions.append(f"step:{step}:advisory:{','.join(d.advisories)}")
            ctx = RunContext(
                run_id=spec.run_id,
                scenario=spec.scenario,
                step=spec.steps,
                metrics=metrics,
                resources=resources,
                tags=tags,
            )
            self._engine.evaluate(Checkpoint.POST_RUN, ctx)
            decisions.append("post_run:allow")
        except GovernanceViolationError as exc:
            halted_by = exc.boundary_id
            decisions.append(f"{exc.severity.lower()}:{exc.boundary_id}")
            manifest = self._manifest(spec, decisions, metrics)
            exc.manifest = manifest  # type: ignore[attr-defined]
            raise
        assert halted_by is None  # noqa: S101 - invariant
        return self._manifest(spec, decisions, metrics)

    def _manifest(
        self, spec: RunSpec, decisions: list[str], metrics: dict[str, float]
    ) -> TrainingManifest:
        """Assemble the manifest, pointing at the current audit head."""
        audit = list(self._engine._audit)
        return TrainingManifest(
            run_id=spec.run_id,
            scenario=spec.scenario,
            root_seed=spec.root_seed,
            git_commit=spec.git_commit,
            config_hash=spec.config_hash,
            env_lock_hash=spec.env_lock_hash,
            dataset_hash=spec.dataset_hash,
            dependencies=spec.dependencies,
            governance_decisions=tuple(decisions),
            finished_at=datetime.now(UTC),
            final_metrics=dict(metrics),
            audit_head=audit[-1].id if audit else "",
        )
