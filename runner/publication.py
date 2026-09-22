"""Fail-closed validation for immutable benchmark evidence packages."""

from __future__ import annotations

import hashlib
import json
import re
import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from runner.run import ATTACK_ORDER, STATUS_VALUES


SYNTHETIC_SECRET = re.compile(rb"sk-proj-[A-Z0-9]{48}")
MACHINE_PATH = re.compile(rb"/(?:Users|home|private/tmp|tmp)/[^\s\"']+")


def _records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate_publication(
    run_dir: Path,
    *,
    expected_systems: tuple[str, ...] = ("atmem",),
    expected_trials: int = 100,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    manifest = json.loads((run_dir / "benchmark-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("harness_worktree_dirty_at_run") is not False:
        raise ValueError("canonical publication requires a clean harness commit")
    records = _records(run_dir / "raw-trials.jsonl")
    expected = len(expected_systems) * len(ATTACK_ORDER) * expected_trials
    if len(records) != expected:
        raise ValueError(f"expected {expected} raw trials, found {len(records)}")
    identities = [
        (row["system"], row["attack_id"], int(row["trial_n"]), int(row["seed"]))
        for row in records
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("raw trials contain duplicate identities")
    counts = Counter((row["system"], row["attack_id"]) for row in records)
    expected_pairs = {
        (system, attack): expected_trials for system in expected_systems for attack in ATTACK_ORDER
    }
    if counts != Counter(expected_pairs):
        raise ValueError(f"raw trial matrix is incomplete: {dict(counts)}")
    invalid = sorted({str(row.get("status")) for row in records} - STATUS_VALUES)
    if invalid:
        raise ValueError(f"invalid trial statuses: {invalid}")
    for frozen in (run_dir / "attack-definitions").glob("*.yaml"):
        source = Path(__file__).resolve().parents[1] / "attacks" / frozen.name
        if not source.exists() or source.read_bytes() != frozen.read_bytes():
            raise ValueError(f"frozen attack definition drift: {frozen.name}")
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file()):
        content = path.read_bytes()
        if SYNTHETIC_SECRET.search(content):
            raise ValueError(f"plaintext synthetic secret found in {path.relative_to(run_dir)}")
        if MACHINE_PATH.search(content):
            raise ValueError(f"machine-specific absolute path found in {path.relative_to(run_dir)}")
    checksum_path = run_dir / "SHA256SUMS"
    if not checksum_path.exists():
        raise ValueError("SHA256SUMS is missing")
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        candidate = run_dir / relative
        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            raise ValueError(f"checksum mismatch: {relative}")
    return {
        "valid": True,
        "run_id": manifest["run_id"],
        "trial_count": len(records),
        "statuses": dict(sorted(Counter(row["status"] for row in records).items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--trials", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(validate_publication(args.run_dir, expected_trials=args.trials), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
