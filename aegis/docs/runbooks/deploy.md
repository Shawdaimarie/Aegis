# Runbook: first deployment

Prerequisite: the CI pipeline is green on `main`. Never deploy from a dirty tree.

## Fly.io (about two minutes)
    fly launch --no-deploy --copy-config
    fly secrets set AEGIS_API_TOKEN=$(openssl rand -base64 32)
    fly deploy
    fly open /console/
Retrieve the token with `fly secrets list` (hashes only) or keep the value you generated.

## Render
Push the repo to GitHub, create a Blueprint from `render.yaml`. Render generates the token;
copy it from the service's Environment tab and paste it into the console's token field.

## After deploy
1. `GET /healthz` returns `{"status":"ok"}`.
2. `/console/` loads, token connects, boundaries render.
3. Run a simulation with `gpu_hours_per_step = 1000`; confirm outcome `halt:gpu-hours-ceiling`.
4. Open the Audit chain tab; confirm `chain verified`.
Record the URL and commit hash in `docs/assessments/`.
