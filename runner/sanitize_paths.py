#!/usr/bin/env python3
"""Create a publication package by relativizing evidence traceback paths only."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runner.report import aggregate, read_trials, write_checksums


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_inventory(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): sha256(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def trial_key(record: dict[str, Any]) -> tuple[str, str, int]:
    return record["system"], record["attack_id"], int(record["trial_n"])


def status_cells(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        f"{item['system']}:{item['attack_id']}": {
            "status": item["status"],
            "trials": item["trials"],
            "trial_status_counts": item["trial_status_counts"],
            "assertion_counts": item["assertion_counts"],
        }
        for item in result["results"]
    }


def replace_workspace_prefix(path: Path, prefix: bytes) -> tuple[int, Counter[str]]:
    original = path.read_bytes()
    suffix_pattern = re.compile(re.escape(prefix) + rb"([A-Za-z0-9_./-]+)")
    suffixes = Counter(
        match.group(1).decode("utf-8", errors="replace")
        for match in suffix_pattern.finditer(original)
    )
    replaced = original.replace(prefix, b"")
    count = sum(suffixes.values())
    if count:
        path.write_bytes(replaced)
    return count, suffixes


def sanitize_package(
    base_dir: Path,
    output_dir: Path,
    *,
    source_root: Path,
    base_archive: Path,
    base_archive_sha256: str,
    package_version: str,
) -> Path:
    if output_dir.exists():
        raise FileExistsError(f"output already exists: {output_dir}")
    observed_archive_sha256 = sha256(base_archive)
    if observed_archive_sha256 != base_archive_sha256:
        raise ValueError(
            f"base archive hash mismatch: expected {base_archive_sha256}, "
            f"observed {observed_archive_sha256}"
        )

    prefix = f"{source_root.resolve().as_posix().rstrip('/')}/".encode()
    base_files = file_inventory(base_dir)
    unexpected = []
    for path in sorted(base_dir.rglob("*")):
        if not path.is_file() or prefix not in path.read_bytes():
            continue
        relative = path.relative_to(base_dir).as_posix()
        if relative != "raw-trials.jsonl" and not relative.startswith("failures/"):
            unexpected.append(relative)
    if unexpected:
        raise ValueError(f"absolute workspace prefix found outside evidence files: {unexpected}")

    shutil.copytree(base_dir, output_dir, copy_function=shutil.copy2)
    raw_path = output_dir / "raw-trials.jsonl"
    raw_replacements, raw_suffixes = replace_workspace_prefix(raw_path, prefix)
    failure_replacements = 0
    failure_suffixes: Counter[str] = Counter()
    modified_evidence_files = []
    if raw_replacements:
        modified_evidence_files.append("raw-trials.jsonl")
    for path in sorted((output_dir / "failures").glob("*.json")):
        count, suffixes = replace_workspace_prefix(path, prefix)
        if count:
            modified_evidence_files.append(path.relative_to(output_dir).as_posix())
            failure_replacements += count
            failure_suffixes.update(suffixes)

    if prefix in raw_path.read_bytes() or any(
        prefix in path.read_bytes() for path in (output_dir / "failures").glob("*.json")
    ):
        raise AssertionError("absolute workspace prefix remains after transformation")

    base_records = read_trials(base_dir / "raw-trials.jsonl")
    new_records = read_trials(raw_path)
    base_by_key = {trial_key(record): record for record in base_records}
    new_by_key = {trial_key(record): record for record in new_records}
    if len(base_by_key) != len(base_records) or len(new_by_key) != len(new_records):
        raise ValueError("duplicate trial keys prevent a path-only comparison")
    if set(base_by_key) != set(new_by_key):
        raise AssertionError("trial keys changed during path sanitization")
    if any(
        base_by_key[key].get("counter_delta") != new_by_key[key].get("counter_delta")
        for key in base_by_key
    ):
        raise AssertionError("a per-trial metric counter changed")

    base_result = aggregate(base_records)
    new_result = aggregate(new_records)
    base_cells = status_cells(base_result)
    new_cells = status_cells(new_result)
    if base_cells != new_cells:
        raise AssertionError("a result cell changed")
    if base_result["metrics"] != new_result["metrics"]:
        raise AssertionError("aggregate metric counters changed")

    base_manifest_path = base_dir / "benchmark-manifest.json"
    manifest = json.loads(base_manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "package_version": package_version,
            "record_count": len(new_records),
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "base_package": {
                "directory": base_dir.name,
                "archive": base_archive.name,
                "archive_sha256": base_archive_sha256,
                "manifest_sha256": sha256(base_manifest_path),
                "raw_trials_sha256": sha256(base_dir / "raw-trials.jsonl"),
            },
            "publication_sanitization": {
                "kind": "absolute_workspace_path_relativization_only",
                "replacement_count": raw_replacements + failure_replacements,
                "modified_evidence_file_count": len(modified_evidence_files),
                "trials_reexecuted": 0,
            },
        }
    )
    (output_dir / "benchmark-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    all_suffixes = raw_suffixes + failure_suffixes
    substitutions = []
    for suffix in sorted(all_suffixes):
        substitutions.append(
            {
                "from": f"<absolute-workspace-root>/{suffix}",
                "to": suffix,
                "raw_trials_occurrences": raw_suffixes[suffix],
                "failure_file_occurrences": failure_suffixes[suffix],
                "total_occurrences": all_suffixes[suffix],
            }
        )
    package_diff = {
        "base_package": base_dir.name,
        "base_archive": base_archive.name,
        "base_archive_sha256": base_archive_sha256,
        "new_package": output_dir.name,
        "transformation": "absolute_workspace_path_relativization_only",
        "trials_reexecuted": 0,
        "trial_integrity": {
            "base_record_count": len(base_records),
            "new_record_count": len(new_records),
            "same_trial_keys": True,
            "per_trial_counter_deltas_equal": True,
            "cell_statuses_equal": True,
            "metric_counters_equal": True,
            "cell_statuses_before": base_cells,
            "cell_statuses_after": new_cells,
            "metric_counters_before": base_result["metrics"],
            "metric_counters_after": new_result["metrics"],
        },
        "path_substitutions": substitutions,
        "modified_evidence_files": modified_evidence_files,
        "modified_evidence_file_count": len(modified_evidence_files),
        "path_substitution_count": raw_replacements + failure_replacements,
        "non_path_evidence_changes": [],
        "derived_metadata_files_regenerated": [
            "PACKAGE-DIFF.json",
            "SHA256SUMS",
            "benchmark-manifest.json",
        ],
        "aggregate_metrics_expected_byte_identical": True,
        "comparison_table_expected_byte_identical": True,
    }
    (output_dir / "PACKAGE-DIFF.json").write_text(
        json.dumps(package_diff, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    persisted_aggregate = json.loads(
        (output_dir / "aggregate-metrics.json").read_text(encoding="utf-8")
    )
    expected_aggregate = dict(new_result)
    if not expected_aggregate.get("metric_exclusions"):
        expected_aggregate.pop("metric_exclusions", None)
    if persisted_aggregate != expected_aggregate:
        raise AssertionError("persisted aggregate metrics do not match raw trial counters")
    write_checksums(output_dir)
    if (base_dir / "aggregate-metrics.json").read_bytes() != (
        output_dir / "aggregate-metrics.json"
    ).read_bytes():
        raise AssertionError("aggregate-metrics.json changed")
    if (base_dir / "generated-comparison-table.md").read_bytes() != (
        output_dir / "generated-comparison-table.md"
    ).read_bytes():
        raise AssertionError("generated comparison table changed")

    allowed_changes = set(modified_evidence_files) | {
        "PACKAGE-DIFF.json",
        "SHA256SUMS",
        "benchmark-manifest.json",
    }
    output_files = file_inventory(output_dir)
    expected_output_files = set(base_files) | {"PACKAGE-DIFF.json"}
    if set(output_files) != expected_output_files:
        added = sorted(set(output_files) - set(base_files))
        removed = sorted(set(base_files) - set(output_files))
        raise AssertionError(
            f"unexpected package file-set change: added={added}, removed={removed}"
        )
    unexpected_changes = sorted(
        path
        for path in base_files
        if base_files[path] != output_files[path] and path not in allowed_changes
    )
    if unexpected_changes:
        raise AssertionError(f"unexpected non-path changes: {unexpected_changes}")
    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--base-archive", required=True, type=Path)
    parser.add_argument("--base-archive-sha256", required=True)
    parser.add_argument("--package-version", required=True)
    args = parser.parse_args()
    output = sanitize_package(
        args.base_dir.resolve(),
        args.output_dir.resolve(),
        source_root=args.source_root.resolve(),
        base_archive=args.base_archive.resolve(),
        base_archive_sha256=args.base_archive_sha256,
        package_version=args.package_version,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
