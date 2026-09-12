"""Fail closed if analysis is absent, incomplete, or contains reported findings."""

import json
from pathlib import Path
import sys


def check(directory: Path) -> int:
    """Read local SARIF output and expose counts without dumping source content."""
    reports = list(directory.glob("*.sarif"))
    if not reports:
        print("FAIL: no CodeQL SARIF report")
        return 1
    count = 0
    for path in reports:
        report = json.loads(path.read_text())
        if report.get("version") != "2.1.0" or not report.get("runs"):
            print("FAIL: invalid or empty CodeQL report")
            return 1
        for run in report["runs"]:
            if any(not invocation.get("executionSuccessful", False)
                   for invocation in run.get("invocations", [])):
                print("FAIL: CodeQL reported incomplete analysis")
                return 1
            findings = run.get("results", [])
            count += len(findings)
            for finding in findings:
                print(json.dumps({"rule": finding.get("ruleId"), "level": finding.get("level")}))
    print(f"CodeQL reports: {len(reports)}; findings: {count}")
    return int(count != 0)


if __name__ == "__main__":
    raise SystemExit(check(Path(sys.argv[1])))
