from hypothesis import given
from hypothesis import strategies as st

from aegis.core.seeding import Seeder


@given(st.integers(min_value=0, max_value=2**63), st.text(min_size=1))
def test_derive_is_deterministic_and_stream_isolated(root, name):
    a, b = Seeder(root), Seeder(root)
    assert a.derive(name) == b.derive(name)
    assert a.derive(name) != a.derive(name + "x")
    assert 0 <= a.derive(name) < 2**63


def test_rng_streams_are_reproducible():
    s1, s2 = Seeder(7), Seeder(7)
    assert [s1.rng("x").random() for _ in range(3)] == [s2.rng("x").random() for _ in range(3)]
