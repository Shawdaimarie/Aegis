# ADR-0001: Boundaries are immutable data, evaluated by a mutation-free engine

status: accepted
date: 2026-08-27

## Context
Safeguards must not be bypassable by configuration drift, runtime patching, or a
well-meaning "escape hatch". Prose policy provides no such guarantee.

## Decision
1. Boundaries are declared only in `configs/governance/*.yaml`, validated by a closed
   Pydantic schema (`extra="forbid"`), loaded into frozen models.
2. `PolicyEngine` takes its boundary set once at construction and exposes exactly two
   public members: `boundaries` (tuple) and `evaluate`. No register/remove/override API.
3. Predicate operators form a closed enumeration; arbitrary code cannot be a boundary.
4. Every evaluation, crossed or clear, is appended to a hash-chained audit log before any
   decision is returned or raised.
5. `test_no_context_override_disables_halt` asserts by property testing that no combination
   of context metrics or tags turns a crossed HALT into an allow.

## Consequences
- Adding a boundary is a reviewed config change, not a code change.
- Compound conditions require multiple boundaries; expressiveness is deliberately limited.
- `test_engine_exposes_no_mutation_surface` fails if the public surface grows, forcing an ADR.
