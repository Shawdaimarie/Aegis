.PHONY: install format lint type docs test security check serve reproduce identity-demo

install:
	uv sync --all-extras

format:
	uv run ruff format src tests scripts examples
	uv run ruff check --fix src tests scripts examples

lint:
	uv run ruff format --check src tests scripts examples
	uv run ruff check src tests scripts examples
	uv run lint-imports

type:
	uv run mypy

docs:
	uv run interrogate -vv src

test:
	uv run pytest

security:
	uv run bandit -ll -r src scripts examples
	uv run pip-audit

check: lint type docs test security

serve:
	AEGIS_API_TOKEN=$${AEGIS_API_TOKEN:?set AEGIS_API_TOKEN} \
	AEGIS_CAPABILITY_SIGNING_KEY=$${AEGIS_CAPABILITY_SIGNING_KEY:?set AEGIS_CAPABILITY_SIGNING_KEY} \
	uv run uvicorn --factory aegis.api.v1.app:create_app --port 8000

identity-demo:
	uv run python examples/agent_identity_demo.py

# Regenerate a manifest from config + seed and compare its content id to the committed one.
reproduce:
	uv run python scripts/run.py --config $(CONFIG) --seed $(SEED) --out /tmp/aegis-repro \
		| cut -f1 \
		| diff - <(python -c "import json;from aegis.training.manifest import TrainingManifest as M;print(M.model_validate(json.load(open('$(TARGET)'))).manifest_id)")
