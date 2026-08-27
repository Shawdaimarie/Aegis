"""Fail CI when a STANDARDS-EXCEPTION marker references an ADR whose expiry has passed."""

import datetime as dt
import re
import sys
from pathlib import Path

MARK = re.compile(r"STANDARDS-EXCEPTION:\s*(ADR-\d{4})")
EXPIRY = re.compile(r"^expires:\s*(\d{4}-\d{2}-\d{2})", re.MULTILINE)


def main() -> int:
    """Scan source for markers and their ADR expiry dates."""
    today = dt.datetime.now(dt.UTC).date()
    failures: list[str] = []
    for f in list(Path("src").rglob("*.py")) + list(Path("scripts").rglob("*.py")):
        for adr in MARK.findall(f.read_text()):
            matches = list(Path("docs/adr").glob(f"{adr.lower()}*.md"))
            if not matches:
                failures.append(f"{f}: {adr} has no ADR file")
                continue
            m = EXPIRY.search(matches[0].read_text())
            if not m:
                failures.append(f"{matches[0]}: missing 'expires:' line")
            elif dt.date.fromisoformat(m.group(1)) < today:
                failures.append(f"{f}: {adr} expired on {m.group(1)}")
    for line in failures:
        sys.stderr.write(line + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
