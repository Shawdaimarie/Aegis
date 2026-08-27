# Engineering Standards and Assessment Rubric

**Status:** Normative. Every rule marked MUST is enforced in CI; a failing check blocks merge.
**Scope:** All code, configuration, documentation, and data artefacts in this repository.
**Languages:** Python (primary), C++ (performance-critical extensions only), JavaScript/HTML (client and documentation surfaces only).

---

## 0. Governing principles

1. **Reproducibility over convenience.** Any result claimed in a paper, README, or dashboard must be regenerable from a commit hash, a pinned environment, and a seed.
2. **Explicit over implicit.** Configuration, dependencies, side effects, and trust boundaries are declared, not discovered.
3. **Secure by construction.** Security properties are enforced by types, validators, and CI gates, not by reviewer vigilance.
4. **One reason per language.** Python is the system language. C++ is admitted only with a benchmark showing a ≥3× improvement on a profiled hotspot. JavaScript/HTML is admitted only for browser-executed surfaces. Any other use requires an Architecture Decision Record (ADR).
5. **Governance is code.** Operational boundaries, safeguards, and policy rules live in versioned, tested modules, never in prose alone.

---

## 1. Repository structure

```
/
├── src/<package>/          # Python source (src layout, no top-level package imports)
│   ├── core/               # Domain logic, no I/O
│   ├── training/           # Independent and dependent training scenarios
│   ├── governance/         # Boundary identification, safeguards, policy engine
│   ├── api/                # Public access points (versioned: v1, v2 ...)
│   ├── adapters/           # All I/O: storage, network, hardware
│   └── _native/            # C++ bindings (pybind11 / nanobind)
├── native/                 # C++ sources, CMake project
├── web/                    # JS/HTML client and docs site
├── tests/                  # Mirrors src/ one-to-one
├── configs/                # Hydra/OmegaConf YAML, schema-validated
├── docs/                   # ADRs, API reference, runbooks
├── scripts/                # Reproducibility entry points only
├── pyproject.toml
├── CMakeLists.txt
├── SECURITY.md
├── STANDARDS.md            # This file
└── CHANGELOG.md
```

- MUST: `src/` layout; the package is never importable from the repo root without installation.
- MUST: `core/` has zero imports from `adapters/`, `api/`, or third-party I/O libraries. Enforced by `import-linter`.
- MUST: every module in `src/` has a corresponding `tests/` module.
- MUST NOT: notebooks in `src/`. Notebooks live in `notebooks/`, are stripped of outputs on commit (`nbstripout`), and are never imported.

---

## 2. Python standards

### 2.1 Toolchain (pinned in `pyproject.toml`)

| Concern | Tool | Gate |
|---|---|---|
| Formatting | `ruff format` | MUST pass, no diff |
| Linting | `ruff check` (rule set below) | MUST pass, zero warnings |
| Typing | `mypy --strict` | MUST pass |
| Security lint | `bandit -ll` | MUST pass |
| Dependency audit | `pip-audit` | MUST pass (no known CVEs) |
| Tests | `pytest` | MUST pass, coverage ≥ 90% lines / 85% branches |
| Docs | `interrogate` | MUST ≥ 95% public docstring coverage |
| Import architecture | `import-linter` | MUST pass |
| Env lock | `uv lock` | MUST be committed and current |

Ruff rule selection: `E, F, W, I, N, UP, B, A, C4, SIM, PT, RET, S, PL, RUF, D, ANN, T20`.
`T20` (no `print`) is absolute: all output goes through `structlog`.

### 2.2 Language rules

- MUST: Python ≥ 3.12. Use `type` statements, `match`, `TypedDict`, `Protocol`, `Self`.
- MUST: full type annotations on every function, method, and public attribute. `Any` requires an inline `# noqa: ANN401` with a justification comment.
- MUST: `from __future__ import annotations` is *not* used (3.12 makes it unnecessary; its presence causes runtime-type ambiguity for Pydantic).
- MUST: immutable data by default. `@dataclass(frozen=True, slots=True)` or Pydantic `BaseModel` with `frozen=True`. Mutable state is confined to explicitly named `*State` classes.
- MUST: no bare `except:`; no `except Exception:` outside top-level entry points. Catch the narrowest type and re-raise as a domain exception from `core.errors`.
- MUST: domain exceptions inherit from a single `PlatformError` root; every public function documents the exceptions it raises.
- MUST NOT: mutable default arguments, `global`, `eval`, `exec`, `pickle` on untrusted input, `subprocess` with `shell=True`.
- MUST: docstrings in Google style. Every public function documents Args, Returns, Raises. Every module has a module-level docstring stating its responsibility in one sentence.
- SHOULD: functions ≤ 40 statements, cyclomatic complexity ≤ 10 (`PLR0915`, `C901`). Exceeding either requires a `# noqa` with reason.

### 2.3 Concurrency

- MUST: `asyncio` for I/O concurrency; `concurrent.futures.ProcessPoolExecutor` or native extensions for CPU. Never `threading` for CPU work.
- MUST: every `async` function is cancellation-safe; resources use `async with`.
- MUST: no blocking calls inside `async` functions (`ruff` `ASYNC` rules).

---

## 3. C++ standards (native extensions)

- MUST: C++20, compiled with `-Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion`.
- MUST: `clang-format` (Google style base, 100 col) and `clang-tidy` with `cppcoreguidelines-*, bugprone-*, performance-*, modernize-*` — zero warnings.
- MUST: sanitiser builds (`-fsanitize=address,undefined`) run in CI on every merge.
- MUST: no raw `new`/`delete`; ownership via `std::unique_ptr`/`std::shared_ptr`; spans and views for non-owning access.
- MUST: no exceptions cross the language boundary un-translated; every binding maps C++ exceptions to `PlatformError` subclasses.
- MUST: every extension ships with a pure-Python reference implementation and a property-based equivalence test (`hypothesis`) proving identical outputs.
- MUST: admission requires an ADR containing the profiling trace and benchmark showing ≥3× speed-up on a representative workload.
- MUST: `constexpr`/`noexcept` where applicable; `[[nodiscard]]` on all non-void functions.
- MUST NOT: platform-specific code outside `#ifdef` blocks with a documented fallback.

---

## 4. JavaScript / HTML standards (client and docs)

- MUST: TypeScript in `strict` mode for any file > 20 lines; plain JS only for trivial glue.
- MUST: `eslint` (`@typescript-eslint/recommended-type-checked`, `eslint-plugin-security`) and `prettier` — zero warnings.
- MUST: no inline scripts or styles; strict Content-Security-Policy (`default-src 'self'`; no `unsafe-inline`, no `unsafe-eval`).
- MUST: HTML validated (`html-validate`); WCAG 2.1 AA (`axe-core` in CI).
- MUST: all user-facing strings externalised for i18n.
- MUST: `npm audit --audit-level=high` clean; lockfile committed; dependencies pinned exactly.
- MUST NOT: dynamic `innerHTML` from any non-constant source; use DOM APIs or a sanitiser (`DOMPurify`).
- MUST NOT: business logic in the client. The client renders and forwards; the API decides.

---

## 5. Security standards

Baseline: OWASP ASVS Level 2 for the API surface, Level 3 for authentication and governance modules. NIST SSDF practices apply to the delivery pipeline.

### 5.1 Code

- MUST: all external input passes through a Pydantic model with explicit constraints before touching domain logic. Validation happens once, at the boundary, in `api/` or `adapters/`.
- MUST: secrets come only from the environment or a secrets manager via `adapters/secrets.py`. `detect-secrets` and `gitleaks` run pre-commit and in CI.
- MUST: cryptography via `cryptography` library only; no hand-rolled primitives; no MD5/SHA-1 for security purposes.
- MUST: parameterised queries; no string-built SQL, shell, or path construction. Path inputs are resolved and checked against an allow-listed root.
- MUST: deserialisation of untrusted data uses `json`, `msgpack` with strict schemas, or `safetensors`. Never `pickle`, `torch.load` without `weights_only=True`, or `yaml.load` without `SafeLoader`.
- MUST: model artefacts are content-addressed (SHA-256) and signature-verified before loading.
- MUST: structured logs never contain secrets, tokens, raw prompts marked sensitive, or PII. A log-redaction processor is mandatory in the `structlog` chain.

### 5.2 API surface

- MUST: authentication on every endpoint (no anonymous routes except `/healthz` and `/version`).
- MUST: rate limiting, request-size limits, and timeouts declared per route.
- MUST: OpenAPI 3.1 spec generated from code and diffed in CI; breaking changes require a major version bump.
- MUST: every response carries a request ID; every request is logged with actor, action, resource, decision.

### 5.3 Supply chain

- MUST: SBOM generated (CycloneDX) on every release.
- MUST: dependencies pinned by hash (`uv lock`); Dependabot/Renovate enabled; upgrades reviewed weekly.
- MUST: CI runs on ephemeral runners with least-privilege tokens; no long-lived credentials in CI.
- MUST: release artefacts signed (Sigstore) and reproducible (identical hash from identical commit).

### 5.4 Process

- MUST: `SECURITY.md` documents disclosure process and response SLA.
- MUST: threat model (STRIDE) maintained in `docs/threat-model.md`, updated with every ADR touching a trust boundary.
- MUST: any PR touching `governance/`, `api/`, or `adapters/secrets.py` requires two reviewers, one designated security owner.

---

## 6. Reproducibility standards

- MUST: every training or evaluation run is launched via `scripts/run.py --config <path> --seed <int>` and nothing else.
- MUST: run metadata captured automatically: git commit (dirty tree forbidden), config hash, environment lock hash, hardware fingerprint, all seeds, wall-clock and resource usage.
- MUST: all randomness flows from a single `Seeder` object; direct calls to `random`, `numpy.random`, `torch.manual_seed` outside `core/seeding.py` are lint errors.
- MUST: deterministic algorithms enabled by default (`torch.use_deterministic_algorithms(True)`); non-determinism is opt-in per run and recorded in metadata.
- MUST: datasets versioned with content hashes and a manifest; raw data never modified in place.
- MUST: configs are typed schemas (Pydantic-backed Hydra structured configs); unknown keys are errors.
- MUST: a `make reproduce TARGET=<result-id>` target regenerates any published figure or table.
- MUST: container image pinned by digest; `Dockerfile` builds from a lockfile, never `pip install <name>` unpinned.

---

## 7. Training-scenario standards

Definitions (normative for the codebase; refine via ADR):

- **Independent scenario:** a model is trained on a partition with no shared parameters, optimiser state, or data with any other model. Isolation is enforced by the `IsolationContext` type; cross-context access raises `IsolationViolation`.
- **Dependent scenario:** models share a declared dependency graph (base weights, adapters, distillation sources). Every edge in the graph is explicit, versioned, and recorded in run metadata.

Rules:

- MUST: scenario type is a required config field; there is no default.
- MUST: personalisation adapters (LoRA or equivalent) are stored separately from base weights and never merged silently.
- MUST: every training entry point emits a `TrainingManifest` artefact listing scenario, dependencies, data hashes, and governance decisions applied.
- MUST: evaluation uses held-out splits whose hashes are asserted disjoint from training splits at runtime.

---

## 8. Governance and boundary standards

The `governance/` package is the executable form of the boundary-identification framework.

- MUST: every boundary is a `Boundary` object with: identifier, formal predicate (a pure function over `RunContext`), severity (`ADVISORY | BLOCKING | HALT`), owner, rationale, and test cases.
- MUST: boundaries are evaluated by the `PolicyEngine` at three checkpoints: pre-run, per-step (configurable cadence), post-run. Evaluation results are immutable, appended to the run's audit log.
- MUST: a `BLOCKING` boundary prevents the run from starting; a `HALT` boundary terminates a run in progress and checkpoints state before exit.
- MUST: boundaries are declared in `configs/governance/*.yaml`, schema-validated, and loaded read-only. Code cannot register boundaries at runtime.
- MUST: safeguards (resource ceilings, egress restrictions, artefact-size limits, prohibited-operation lists) have default values that are conservative; loosening requires an explicit config override that is itself logged.
- MUST: the audit log is append-only, hash-chained, and exportable to an external sink via `adapters/audit.py`.
- MUST: 100% branch coverage on `governance/`. No `noqa`, no `# pragma: no cover`.
- MUST: property-based tests demonstrate that no sequence of config overrides can disable a `HALT` boundary.

---

## 9. Testing standards

- MUST: test pyramid — unit (fast, no I/O, ≥ 80% of tests), integration (adapters against test doubles or containers), end-to-end (one smoke test per public API version).
- MUST: unit tests are hermetic: no network, no filesystem outside `tmp_path`, no wall-clock (`freezegun`).
- MUST: `hypothesis` property tests for every pure function in `core/` with non-trivial input space.
- MUST: golden-output regression tests for every training scenario using a tiny fixture model (< 1 s runtime).
- MUST: mutation testing (`mutmut`) on `core/` and `governance/` with mutation score ≥ 80%.
- MUST: tests are named `test_<unit>_<condition>_<expected>`; one assertion concept per test.
- MUST NOT: `time.sleep` in tests; retry loops that mask flakiness; tests that depend on ordering.
- MUST: flaky tests are quarantined within 24 h and fixed or deleted within one sprint; there is no permanent `@flaky`.

---

## 10. Documentation standards

- MUST: every architectural decision is an ADR (`docs/adr/NNNN-title.md`, MADR format). Superseded ADRs are never deleted.
- MUST: API reference generated from docstrings (`mkdocs` + `mkdocstrings`); build fails on broken cross-references.
- MUST: every runnable script has a `--help` that fully documents arguments.
- MUST: `README.md` contains: one-paragraph purpose, installation in ≤ 5 commands, a 30-second quick-start, link to ADRs, link to this file.
- MUST: runbooks in `docs/runbooks/` for every operational procedure (deploy, rollback, rotate secrets, respond to a `HALT`).
- MUST: prose follows the same review process as code.

---

## 11. Version control and delivery

- MUST: Conventional Commits; commit messages are linted.
- MUST: trunk-based development; branches live < 3 days; PRs < 400 changed lines excluding generated files (larger PRs are split or justified in the description).
- MUST: PR template with sections: Motivation, Change, Risk, Test evidence, Governance impact, ADR link.
- MUST: signed commits (`git commit -S`).
- MUST: semantic versioning; `CHANGELOG.md` updated in the same PR as the change.
- MUST: CI pipeline stages in order: lint → type → unit → security → build native → integration → docs → SBOM → sign. A stage failure stops the pipeline.
- MUST: `main` is always releasable. A red `main` is a P1 incident.

---

## 12. Assessment rubric

Each dimension is scored 0–4. A release requires every dimension ≥ 3 and a total ≥ 40/48. Scores are recorded in `docs/assessments/<version>.md` with evidence links.

| # | Dimension | 0 — Absent | 2 — Partial | 4 — Exemplary |
|---|---|---|---|---|
| 1 | Architecture | No layering; core imports I/O | Layers exist, violations tolerated | `import-linter` clean; ADRs for all cross-layer decisions |
| 2 | Type safety | Untyped | Typed, `Any` common | `mypy --strict`, `Any` < 5 occurrences, all justified |
| 3 | Test rigour | < 60% coverage | ≥ 80% lines | ≥ 90/85 coverage, mutation ≥ 80%, property tests on `core/` |
| 4 | Reproducibility | Results not regenerable | Seeds set, env unpinned | `make reproduce` regenerates every published artefact bit-for-bit |
| 5 | Security posture | No scanning | Scanning, findings unresolved | ASVS L2/L3 checklist complete, threat model current, zero open highs |
| 6 | Governance enforcement | Rules in prose only | Rules in code, partially tested | 100% branch coverage, `HALT` undisableable proven by property tests |
| 7 | API quality | Undocumented | OpenAPI exists | Spec generated, diffed, versioned; breaking changes gated |
| 8 | Native code discipline | C++ without justification | Benchmarked, no sanitisers | ADR + benchmark + sanitiser CI + Python equivalence proof |
| 9 | Client discipline | Logic in browser, inline JS | TS strict, CSP partial | Strict CSP, a11y AA, zero client-side business logic |
| 10 | Documentation | README only | API docs, stale ADRs | ADRs current, runbooks for all ops, docs build gated |
| 11 | Delivery pipeline | Manual releases | CI exists, stages skippable | Ordered gated stages, signed reproducible artefacts, SBOM |
| 12 | Code health | Complexity unbounded | Limits set, many `noqa` | Limits enforced, `noqa` count tracked and decreasing |

---

## 13. Exceptions

Any deviation from a MUST requires:

1. An ADR describing the deviation, its scope, its expiry date (≤ 90 days), and the compensating control.
2. An inline marker `# STANDARDS-EXCEPTION: ADR-NNNN` at each affected site.
3. A CI check that fails when the expiry date passes.

Exceptions with no expiry are not exceptions; they are standards changes and must be made by amending this document.

---

## 14. Amendment

This document is amended by PR with two approvals including the security owner. Every amendment increments the version below and is recorded in `CHANGELOG.md`.

**Version:** 1.0.0
