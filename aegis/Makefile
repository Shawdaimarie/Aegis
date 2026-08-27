.PHONY: install lint type test security check serve reproduce
install: ; uv sync --all-extras
lint: ; uv run ruff format --check src tests scripts && uv run ruff check src tests scripts && uv run lint-imports
type: ; uv run mypy
test: ; uv run pytest
security: ; uv run bandit -ll -r src scripts && uv run pip-audit
check: lint type test security
serve: ; AEGIS_API_TOKEN=$${AEGIS_API_TOKEN:?set a token} uv run uvicorn --factory aegis.api.v1.app:create_app --port 8000
# Regenerate a manifest from config + seed and compare its content id to the committed one.
reproduce: ; uv run python scripts/run.py --config $(CONFIG) --seed $(SEED) --out /tmp/aegis-repro | cut -f1 | diff - <(python -c "import json;from aegis.training.manifest import TrainingManifest as M;print(M.model_validate(json.load(open('$(TARGET)'))).manifest_id)")
