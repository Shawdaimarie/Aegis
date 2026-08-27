"""The TrainingManifest is the reproducibility contract emitted by every run."""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.hashing import content_id
from aegis.core.types import ScenarioKind
from aegis.training.scenarios import DependencyGraph


class TrainingManifest(BaseModel):
    """Everything required to replay a run bit-for-bit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    scenario: ScenarioKind
    root_seed: int
    git_commit: str
    config_hash: str
    env_lock_hash: str
    dataset_hash: str
    dependencies: DependencyGraph | None = None
    governance_decisions: tuple[str, ...] = Field(default_factory=tuple)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    final_metrics: dict[str, float] = Field(default_factory=dict)
    audit_head: str = ""

    @property
    def manifest_id(self) -> str:
        """Content identifier of the run (excludes timestamps and the audit pointer)."""
        body = self.model_dump(mode="json", exclude={"started_at", "finished_at", "audit_head"})
        return content_id(body)
