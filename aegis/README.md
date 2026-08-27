# Aegis

A governed, reproducible AI training and access platform. Every run executes under an
immutable set of operational boundaries; every decision lands in a hash-chained audit log;
every run emits a manifest that replays it bit-for-bit.

## Install
```
uv sync --all-extras
export AEGIS_API_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
make check          # lint, import contracts, types, tests, security
make serve          # API on :8000 · console at /console/ · OpenAPI at /v1/docs
```

## Thirty-second tour
```
python scripts/run.py --config examples/independent.json --seed 42
```
prints a manifest id and path. Run it again with the same seed: the id is identical.
Open `/console/`, paste your token, and watch the audit chain grow as you evaluate
contexts and simulate runs that cross the GPU ceiling.

## Layout
`src/aegis/core` pure domain · `governance` boundary engine and audit chain · `training`
scenarios, runner, manifest · `adapters` all I/O · `api/v1` FastAPI surface · `web` console.

## Governing documents
[STANDARDS.md](STANDARDS.md) · [SECURITY.md](SECURITY.md) · [docs/adr](docs/adr) · [docs/runbooks](docs/runbooks)

## Lineage of the design
The audit log is a hash chain in the sense of Haber and Stornetta (1991), using Merkle-style
content addressing. The boundary engine follows Anderson's reference-monitor concept (1972):
tamper-proof, always invoked, small enough to verify. Constant-time credential comparison
follows Kocher's timing-attack analysis (1996). Supply-chain controls follow NIST SP 800-218
and SLSA. Reproducibility requirements follow the ACM Artifact Review and Badging policy.
