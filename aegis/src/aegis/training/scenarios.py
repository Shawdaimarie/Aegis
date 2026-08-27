"""Scenario primitives. Isolation and dependency are types, not conventions."""

from collections.abc import Iterator

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.core.errors import ConfigurationError, IsolationViolationError


class IsolationContext:
    """Owns resources for an independent run. Cross-context access raises.

    Any object handed to a run is tagged with the context id; retrieving it from a
    different context is an IsolationViolationError regardless of caller intent.
    """

    def __init__(self, context_id: str) -> None:
        """Create an empty, named context."""
        self.context_id = context_id
        self._store: dict[str, tuple[str, object]] = {}

    def put(self, key: str, value: object) -> None:
        """Store ``value`` under ``key``, owned by this context."""
        self._store[key] = (self.context_id, value)

    def get(self, key: str, *, requesting_context: str) -> object:
        """Retrieve ``key`` only if ``requesting_context`` owns it.

        Raises:
            IsolationViolationError: Owner mismatch.
            KeyError: Unknown key.
        """
        owner, value = self._store[key]
        if owner != requesting_context:
            raise IsolationViolationError(
                f"context '{requesting_context}' attempted to read '{key}' owned by '{owner}'"
            )
        return value


class DependencyEdge(BaseModel):
    """One explicit dependency between artefacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    target: str
    kind: str = Field(pattern=r"^(base-weights|adapter|distillation|data)$")
    source_version: str


class DependencyGraph(BaseModel):
    """Declared, acyclic dependency graph for a dependent scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edges: tuple[DependencyEdge, ...]

    @model_validator(mode="after")
    def _acyclic(self) -> "DependencyGraph":
        """Reject cycles by depth-first colouring."""
        adjacency: dict[str, list[str]] = {}
        for e in self.edges:
            adjacency.setdefault(e.source, []).append(e.target)
        state: dict[str, int] = {}

        def visit(n: str) -> None:
            """Visit ``n``; raise on a back edge."""
            if state.get(n) == 1:
                raise ConfigurationError(f"dependency cycle through '{n}'")
            if state.get(n) == 2:  # noqa: PLR2004 - 0/1/2 DFS colouring
                return
            state[n] = 1
            for m in adjacency.get(n, []):
                visit(m)
            state[n] = 2

        for node in adjacency:
            visit(node)
        return self

    def upstream_of(self, target: str) -> Iterator[DependencyEdge]:
        """Yield edges that feed ``target``."""
        return (e for e in self.edges if e.target == target)
