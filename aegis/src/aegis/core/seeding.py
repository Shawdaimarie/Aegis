"""Single source of randomness for the platform.

Every random number generator used by any run is derived from one root seed via
this module, which makes any run replayable from its manifest.
"""

import hashlib
import random
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Seeder:
    """Derives named, independent sub-seeds from a single root seed."""

    root: int
    _cache: dict[str, int] = field(default_factory=dict, compare=False, repr=False)

    def derive(self, name: str) -> int:
        """Return a stable 63-bit seed for a named stream.

        Args:
            name: Stream label, e.g. ``"data-shuffle"`` or ``"init"``.

        Returns:
            Deterministic integer seed for that stream.
        """
        if name not in self._cache:
            digest = hashlib.sha256(f"{self.root}:{name}".encode()).digest()
            self._cache[name] = int.from_bytes(digest[:8], "big") >> 1
        return self._cache[name]

    def rng(self, name: str) -> random.Random:
        """Return an isolated ``random.Random`` for a named stream."""
        return random.Random(self.derive(name))  # noqa: S311 - non-cryptographic by design
