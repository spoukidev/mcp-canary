"""Simple analyzer for canary_events.jsonl."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "canary_events.jsonl")
    if not path.exists():
        print(f"No log file at {path}")
        return

    sessions: dict[str, list[dict]] = defaultdict(list)
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
            sessions[ev.get("session", "unknown")].append(ev)
        except json.JSONDecodeError:
            continue

    for sid, events in sessions.items():
        severities = [e.get("severity", "info") for e in events]
        max_sev = max(severities, key=lambda s: ["info", "medium", "high", "critical"].index(s) if s in ["info", "medium", "high", "critical"] else 0)
        print(f"\nSession {sid} — {len(events)} events — max severity: {max_sev}")
        for e in events:
            flags = ",".join(e.get("flags") or []) or "-"
            print(f"  [{e.get('severity', '?'):8}] {flags:20} {e.get('tool')} {e.get('args', {})}")


if __name__ == "__main__":
    main()
