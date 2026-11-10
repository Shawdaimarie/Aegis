# Aegis — Python policy service

A Python reference implementation for policy decisions, governance, and training experiments. This is distinct from the Go Aegis gateway in Sentinel.

## Reproduce locally

Use Python 3.12 or newer. From `aegis/`, create a virtual environment and run:

```sh
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e '.[dev]'
python -m pytest
python -m ruff check src tests
python -m mypy src
```

See [service documentation](aegis/README.md) for API behavior and limitations. Local tests do not establish production capacity or independent security review.
