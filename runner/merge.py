#!/usr/bin/env python3
"""Merge complete system shards without synthesising or rewriting trial records."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runner.report import ATTACK_ORDER, SYSTEM_ORDER, read_trials, report


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_revision() -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip())
    return revision, dirty


def merge_shards(
    shard_dirs: list[Path],
    output_dir: Path,
    *,
    required_systems: list[str],
    required_attacks: list[str],
    required_trials: int,
) -> Path:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"output evidence directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifests = []
    records = []
    configurations: dict[str, dict[str, Any]] = {}
    attack_sources: dict[str, bytes] = {}
    environment_lock: bytes | None = None

    for shard in shard_dirs:
        manifest_path = shard / "benchmark-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifests.append((shard, manifest, sha256(manifest_path)))
        records.extend(read_trials(shard / "raw-trials.jsonl"))
        for path in (shard / "system-configurations").glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if path.stem in configurations and configurations[path.stem] != value:
                raise ValueError(f"conflicting configuration for {path.stem}")
            configurations[path.stem] = value
        for path in (shard / "attack-definitions").glob("*.yaml"):
            payload = path.read_bytes()
            if path.name in attack_sources and attack_sources[path.name] != payload:
                raise ValueError(f"conflicting attack definition: {path.name}")
            attack_sources[path.name] = payload
        lock = (shard / "environment.lock").read_bytes()
        if environment_lock is not None and environment_lock != lock:
            raise ValueError("shards have different environment.lock files")
        environment_lock = lock

    run_ids = {manifest["run_id"] for _, manifest, _ in manifests} | {record["run_id"] for record in records}
    seeds = {manifest["seed"] for _, manifest, _ in manifests}
    revisions = {manifest["harness_commit"] for _, manifest, _ in manifests}
    if len(run_ids) != 1 or len(seeds) != 1:
        raise ValueError(
            f"incompatible shards: run_ids={sorted(run_ids)}, seeds={sorted(seeds)}, revisions={sorted(revisions)}"
        )
    if any(manifest.get("harness_worktree_dirty_at_run") for _, manifest, _ in manifests):
        raise ValueError("at least one shard ran from a dirty harness worktree")

    key_counts = Counter(
        (record["system"], record["attack_id"], int(record["trial_n"])) for record in records
    )
    duplicates = [key for key, count in key_counts.items() if count != 1]
    if duplicates:
        raise ValueError(f"duplicate trial keys: {duplicates[:10]}")
    pair_counts = Counter((record["system"], record["attack_id"]) for record in records)
    expected_pairs = {(system, attack) for system in required_systems for attack in required_attacks}
    unexpected = set(pair_counts) - expected_pairs
    incomplete = {
        pair: pair_counts.get(pair, 0)
        for pair in sorted(expected_pairs)
        if pair_counts.get(pair, 0) != required_trials
    }
    expected_trial_numbers = set(range(1, required_trials + 1))
    wrong_trial_numbers = {
        pair: sorted(
            int(record["trial_n"])
            for record in records
            if (record["system"], record["attack_id"]) == pair
        )
        for pair in sorted(expected_pairs)
        if {
            int(record["trial_n"])
            for record in records
            if (record["system"], record["attack_id"]) == pair
        } != expected_trial_numbers
    }
    if unexpected or incomplete or wrong_trial_numbers:
        raise ValueError(
            f"shards are not complete: unexpected={sorted(unexpected)}, "
            f"counts={incomplete}, trial_numbers={wrong_trial_numbers}"
        )

    records.sort(
        key=lambda item: (
            SYSTEM_ORDER.index(item["system"]),
            ATTACK_ORDER.index(item["attack_id"]),
            int(item["trial_n"]),
        )
    )
    raw_path = output_dir / "raw-trials.jsonl"
    raw_path.write_text(
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    config_dir = output_dir / "system-configurations"
    config_dir.mkdir()
    for system, value in configurations.items():
        (config_dir / f"{system}.json").write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    attack_dir = output_dir / "attack-definitions"
    attack_dir.mkdir()
    for name, payload in sorted(attack_sources.items()):
        (attack_dir / name).write_bytes(payload)
    (output_dir / "environment.lock").write_bytes(environment_lock or b"")

    first = manifests[0][1]
    merge_commit, merge_dirty = git_revision()
    final_manifest = {
        "run_id": next(iter(run_ids)),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": next(iter(seeds)),
        "harness_commit": next(iter(revisions)) if len(revisions) == 1 else None,
        "harness_commits": sorted(revisions),
        "harness_worktree_dirty_at_run": False,
        "merge_report_commit": merge_commit,
        "merge_report_worktree_dirty": merge_dirty,
        "systems": required_systems,
        "attacks": required_attacks,
        "record_count": len(records),
        "required_trials_per_pair": required_trials,
        "adapter_targets": {
            system: {
                "adapter_version": configurations[system].get("version"),
                "target_commit": configurations[system].get("target_commit"),
            }
            for system in required_systems
        },
        "environment": first.get("environment") or {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "merged_shards": [
            {
                "directory": shard.name,
                "harness_commit": shard_manifest["harness_commit"],
                "manifest_sha256": digest,
                "raw_trials_sha256": sha256(shard / "raw-trials.jsonl"),
            }
            for shard, shard_manifest, digest in manifests
        ],
        "merge_rule": "records copied and sorted by system/attack/trial; none synthesized",
        "narrative_generated_by_agent": False,
    }
    (output_dir / "benchmark-manifest.json").write_text(
        json.dumps(final_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report(output_dir)
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--systems", required=True)
    parser.add_argument("--attacks", required=True)
    parser.add_argument("--required-trials", required=True, type=int)
    args = parser.parse_args()
    output = merge_shards(
        [path.resolve() for path in args.shard],
        args.output_dir.resolve(),
        required_systems=[item for item in SYSTEM_ORDER if item in args.systems.split(",")],
        required_attacks=[item for item in ATTACK_ORDER if item in args.attacks.split(",")],
        required_trials=args.required_trials,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
