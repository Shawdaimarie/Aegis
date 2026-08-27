"""Sole entry point for launching a run. Everything else is a library."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from aegis.core.types import ScenarioKind
from aegis.governance.audit import AuditLog
from aegis.governance.engine import PolicyEngine
from aegis.governance.loader import load_boundaries
from aegis.training.runner import Runner, RunSpec


def _git_commit() -> str:
    out = subprocess.run(  # noqa: S603 - fixed argv, no user input, no shell
        [shutil.which("git") or "/usr/bin/git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() or "0" * 40


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run under governance, write the manifest."""
    p = argparse.ArgumentParser(description="Launch a governed Aegis run.")
    p.add_argument("--config", type=Path, required=True, help="Run config JSON (schema: RunSpec).")
    p.add_argument("--seed", type=int, required=True, help="Root seed. Overrides config.")
    p.add_argument("--governance", type=Path, default=Path("configs/governance/default.yaml"))
    p.add_argument("--out", type=Path, default=Path("runs"))
    args = p.parse_args(argv)

    raw = args.config.read_bytes()
    cfg = json.loads(raw)
    cfg["root_seed"] = args.seed
    cfg.setdefault("git_commit", _git_commit())
    cfg["config_hash"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    lock = Path("uv.lock")
    cfg.setdefault(
        "env_lock_hash",
        "sha256:" + hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else "unlocked",
    )
    spec = RunSpec.model_validate(cfg)

    audit = AuditLog()
    runner = Runner(PolicyEngine(load_boundaries(args.governance), audit))

    def step(i: int, _: object) -> dict[str, float]:
        return {"loss": 2.0 * (0.98**i), "res:gpu_hours": 0.01 * i}

    manifest = runner.run(spec, step)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / f"{spec.run_id}.manifest.json"
    target.write_text(manifest.model_dump_json(indent=2))
    sys.stdout.write(f"{manifest.manifest_id}\t{target}\n")
    return 0 if spec.scenario in ScenarioKind else 1


if __name__ == "__main__":
    raise SystemExit(main())
