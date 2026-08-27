# ADR-0002: Language admission

status: accepted
date: 2026-08-27

## Decision
Python is the system language. C++ is admitted only behind pybind11/nanobind with a profiling
trace showing a ≥3× speed-up on a hotspot, a pure-Python reference implementation, and a
property-based equivalence test. JavaScript is admitted only for browser-executed surfaces
(`web/`) and carries no business logic.

## Consequences
The repository currently contains no C++. Every line is under strict typing and 90%+ test
coverage; the first native extension arrives with its own evidence and its own ADR.
