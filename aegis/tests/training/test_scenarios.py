import pytest

from aegis.core.errors import ConfigurationError, IsolationViolationError
from aegis.training.scenarios import DependencyEdge, DependencyGraph, IsolationContext


def test_isolation_context_blocks_cross_access():
    a = IsolationContext("a")
    a.put("weights", object())
    assert a.get("weights", requesting_context="a") is not None
    with pytest.raises(IsolationViolationError):
        a.get("weights", requesting_context="b")


def test_dependency_graph_rejects_cycles():
    e = DependencyEdge
    with pytest.raises(ConfigurationError, match="cycle"):
        DependencyGraph(
            edges=(
                e(source="a", target="b", kind="adapter", source_version="1"),
                e(source="b", target="a", kind="adapter", source_version="1"),
            )
        )


def test_dependency_graph_upstream():
    g = DependencyGraph(
        edges=(
            DependencyEdge(source="base", target="ft", kind="base-weights", source_version="v1"),
        )
    )
    assert [x.source for x in g.upstream_of("ft")] == ["base"]
