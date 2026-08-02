#!/usr/bin/env python3
"""Create a versioned evidence revision by replacing exact trial-key sets."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
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
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip())
    return revision, dirty


def trial_key(record: dict[str, Any]) -> tuple[str, str, int]:
    return record["system"], record["attack_id"], int(record["trial_n"])


def status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(record["status"] for record in records).items()))


def copy_tree_files(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def file_inventory(directory: Path) -> dict[str, str]:
    excluded = {"SHA256SUMS", "PACKAGE-DIFF.json"}
    return {
        path.relative_to(directory).as_posix(): sha256(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name not in excluded
    }


def revise_package(
    base_dir: Path,
    replacement_dirs: list[Path],
    output_dir: Path,
    *,
    replacement_pairs: set[tuple[str, str]],
    package_version: str,
    base_archive: Path,
    base_archive_sha256: str,
    assertion_correction: dict[str, str] | None = None,
) -> Path:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"output evidence directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    observed_base_archive_sha256 = sha256(base_archive)
    if observed_base_archive_sha256 != base_archive_sha256:
        raise ValueError(
            f"base archive hash mismatch: expected {base_archive_sha256}, "
            f"observed {observed_base_archive_sha256}"
        )

    base_manifest_path = base_dir / "benchmark-manifest.json"
    base_manifest = json.loads(base_manifest_path.read_text(encoding="utf-8"))
    base_records = read_trials(base_dir / "raw-trials.jsonl")
    base_by_key = {trial_key(record): record for record in base_records}
    if len(base_by_key) != len(base_records):
        raise ValueError("base package contains duplicate trial keys")

    replacement_records: list[dict[str, Any]] = []
    replacement_manifests: list[tuple[Path, dict[str, Any]]] = []
    replacement_configs: dict[str, bytes] = {}
    replacement_attacks: dict[str, bytes] = {}
    replacement_lock: bytes | None = None
    for directory in replacement_dirs:
        manifest = json.loads((directory / "benchmark-manifest.json").read_text(encoding="utf-8"))
        if manifest.get("harness_worktree_dirty_at_run"):
            raise ValueError(f"replacement shard ran dirty: {directory}")
        if manifest["run_id"] != base_manifest["run_id"] or manifest["seed"] != base_manifest["seed"]:
            raise ValueError(f"replacement shard run/seed mismatch: {directory}")
        replacement_manifests.append((directory, manifest))
        replacement_records.extend(read_trials(directory / "raw-trials.jsonl"))
        for path in (directory / "system-configurations").glob("*.json"):
            payload = path.read_bytes()
            if path.name in replacement_configs and replacement_configs[path.name] != payload:
                raise ValueError(f"replacement configuration conflict: {path.name}")
            replacement_configs[path.name] = payload
        for path in (directory / "attack-definitions").glob("*.yaml"):
            payload = path.read_bytes()
            if path.name in replacement_attacks and replacement_attacks[path.name] != payload:
                raise ValueError(f"replacement attack conflict: {path.name}")
            replacement_attacks[path.name] = payload
        lock = (directory / "environment.lock").read_bytes()
        if replacement_lock is not None and replacement_lock != lock:
            raise ValueError("replacement shards have different environment locks")
        replacement_lock = lock

    replacement_by_key = {trial_key(record): record for record in replacement_records}
    if len(replacement_by_key) != len(replacement_records):
        raise ValueError("replacement shards contain duplicate trial keys")
    if {key[:2] for key in replacement_by_key} != replacement_pairs:
        raise ValueError("replacement shards contain an unexpected system/attack pair")
    for pair in replacement_pairs:
        numbers = {key[2] for key in replacement_by_key if key[:2] == pair}
        if numbers != set(range(1, 101)):
            raise ValueError(f"replacement pair is incomplete: {pair} => {sorted(numbers)}")
    missing_base_keys = set(replacement_by_key) - set(base_by_key)
    if missing_base_keys:
        raise ValueError(f"replacement keys absent from base package: {sorted(missing_base_keys)[:10]}")

    revised_by_key = dict(base_by_key)
    revised_by_key.update(replacement_by_key)
    revised_records = sorted(
        revised_by_key.values(),
        key=lambda item: (
            SYSTEM_ORDER.index(item["system"]),
            ATTACK_ORDER.index(item["attack_id"]),
            int(item["trial_n"]),
        ),
    )
    if len(revised_records) != len(base_records):
        raise AssertionError("revision changed total record count")
    (output_dir / "raw-trials.jsonl").write_text(
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in revised_records),
        encoding="utf-8",
    )

    copy_tree_files(base_dir / "system-configurations", output_dir / "system-configurations")
    for name, payload in replacement_configs.items():
        (output_dir / "system-configurations" / name).write_bytes(payload)
    copy_tree_files(base_dir / "attack-definitions", output_dir / "attack-definitions")
    base_l = output_dir / "attack-definitions" / "L-secret-ingestion.yaml"
    legacy_zep_l = output_dir / "attack-definitions" / "legacy-zep-L-secret-ingestion.yaml"
    if not legacy_zep_l.exists():
        legacy_zep_l.write_bytes(base_l.read_bytes())
    for name, payload in replacement_attacks.items():
        (output_dir / "attack-definitions" / name).write_bytes(payload)
    if replacement_lock is not None and replacement_lock != (base_dir / "environment.lock").read_bytes():
        raise ValueError("replacement environment differs from base package")
    shutil.copy2(base_dir / "environment.lock", output_dir / "environment.lock")
    shutil.copy2(ROOT / "README.md", output_dir / "README.md")
    capabilities_dir = output_dir / "adapter-capabilities"
    for system in ("mem0", "zep", "letta"):
        target = capabilities_dir / system / "CAPABILITIES.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "adapters" / system / "CAPABILITIES.md", target)

    revision_commit, revision_dirty = git_revision()
    pair_changes = []
    for system, attack in sorted(replacement_pairs):
        old = [record for key, record in base_by_key.items() if key[:2] == (system, attack)]
        new = [record for key, record in replacement_by_key.items() if key[:2] == (system, attack)]
        pair_changes.append({
            "system": system,
            "attack_id": attack,
            "trial_count": len(new),
            "old_status_counts": status_counts(old),
            "new_status_counts": status_counts(new),
        })
    manifest = {
        "run_id": base_manifest["run_id"],
        "package_version": package_version,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": base_manifest["seed"],
        "systems": base_manifest["systems"],
        "attacks": base_manifest["attacks"],
        "record_count": len(revised_records),
        "base_package": {
            "directory": base_dir.name,
            "archive": base_archive.name,
            "archive_sha256": base_archive_sha256,
            "manifest_sha256": sha256(base_manifest_path),
            "raw_trials_sha256": sha256(base_dir / "raw-trials.jsonl"),
        },
        "revision_commit": revision_commit,
        "revision_worktree_dirty": revision_dirty,
        "trial_revision": {
            "replaced_records": len(replacement_by_key),
            "unchanged_records": len(base_records) - len(replacement_by_key),
            "pairs": pair_changes,
            "zep_L": "carried forward unchanged as N/A per gate-4 instruction; legacy YAML frozen separately",
        },
        "assertion_correction": assertion_correction,
        "replacement_shards": [
            {
                "directory": directory.name,
                "harness_commit": shard_manifest["harness_commit"],
                "manifest_sha256": sha256(directory / "benchmark-manifest.json"),
                "raw_trials_sha256": sha256(directory / "raw-trials.jsonl"),
            }
            for directory, shard_manifest in replacement_manifests
        ],
        "attack_definition_provenance": {
            "mem0:L": "attack-definitions/L-secret-ingestion.yaml",
            "letta:L": "attack-definitions/L-secret-ingestion.yaml",
            "zep:L": "attack-definitions/legacy-zep-L-secret-ingestion.yaml",
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "revision_rule": "exact key replacement; no missing trial synthesized and no unchanged trial rewritten",
        "narrative_generated_by_agent": False,
    }
    (output_dir / "benchmark-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report(output_dir)
    base_inventory = file_inventory(base_dir)
    new_inventory = file_inventory(output_dir)
    added = sorted(set(new_inventory) - set(base_inventory))
    removed = sorted(set(base_inventory) - set(new_inventory))
    modified = sorted(
        name for name in set(base_inventory) & set(new_inventory)
        if base_inventory[name] != new_inventory[name]
    )
    package_diff = {
        "base_package": base_dir.name,
        "new_package": output_dir.name,
        "trial_record_changes": pair_changes,
        "unchanged_trial_records": len(base_records) - len(replacement_by_key),
        "replaced_trial_records": len(replacement_by_key),
        "assertion_correction": assertion_correction,
        "added_files": added,
        "removed_files": removed,
        "modified_files": modified,
        "derived_files_regenerated_after_this_inventory": ["PACKAGE-DIFF.json", "SHA256SUMS"],
    }
    (output_dir / "PACKAGE-DIFF.json").write_text(
        json.dumps(package_diff, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report(output_dir)
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", required=True, type=Path)
    parser.add_argument("--replacement-shard", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--replace", action="append", required=True, help="system:attack")
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--base-archive", required=True, type=Path)
    parser.add_argument("--base-archive-sha256", required=True)
    parser.add_argument("--correction-id")
    parser.add_argument("--correction-summary")
    parser.add_argument("--old-definition")
    parser.add_argument("--new-definition")
    args = parser.parse_args()
    correction_values = {
        "id": args.correction_id,
        "summary": args.correction_summary,
        "old_definition": args.old_definition,
        "new_definition": args.new_definition,
    }
    if any(correction_values.values()) and not all(correction_values.values()):
        parser.error("all four assertion-correction arguments are required together")
    assertion_correction = correction_values if all(correction_values.values()) else None
    pairs = {tuple(value.split(":", 1)) for value in args.replace}
    output = revise_package(
        args.base_dir.resolve(),
        [path.resolve() for path in args.replacement_shard],
        args.output_dir.resolve(),
        replacement_pairs=pairs,
        package_version=args.package_version,
        base_archive=args.base_archive.resolve(),
        base_archive_sha256=args.base_archive_sha256,
        assertion_correction=assertion_correction,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
