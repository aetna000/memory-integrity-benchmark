#!/usr/bin/env python3
"""Build a human-review index for non-PASS trials outside the evidence package."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from runner.report import read_trials


NATIVE_SURFACES = {
    "mem0": {
        "ingest": "MemoryClient.add(infer=True)",
        "recall": "MemoryClient.search",
        "authority": "no native protected-procedure or approval object mapped",
    },
    "zep": {
        "ingest": "thread.add_messages with native user/assistant roles",
        "settle": "thread.get message.processed, 300 second bound",
        "recall": "graph.search(scope='episodes')",
        "authority": "no native protected-procedure or approval object mapped",
    },
    "letta": {
        "ingest": "agents.messages.create with native message roles",
        "recall": "messages.search(search_mode='hybrid')",
        "authority": "no native protected-procedure or approval object mapped",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classification_reason(record: dict[str, Any], configuration: dict[str, Any]) -> str:
    status = record["status"]
    if status == "NOT_REPRESENTABLE":
        missing = ", ".join(record.get("missing_capabilities") or [])
        return (
            f"YAML requirements are absent from the adapter capability declaration: {missing}. "
            "The adapter does not emulate those concepts with metadata."
        )
    if status == "NOT_SUPPORTED":
        return "The concept is representable, but the mapped public API did not expose the required operation."
    if status == "ERROR":
        error = record.get("error") or {}
        return (
            "The native operation did not reach assertion evaluation; the trial remains ERROR. "
            f"Observed {error.get('type', 'unknown error')}: {error.get('message', '')}"
        )
    if status in {"FAIL", "PARTIAL"}:
        failed = [item["kind"] for item in record.get("assertions") or [] if not item.get("pass")]
        return f"Native outputs were observed and these assertions did not hold: {', '.join(failed)}."
    raise ValueError(f"not a non-PASS status: {status}")


def build_review(run_dir: Path, output_dir: Path) -> tuple[Path, Path]:
    records = read_trials(run_dir / "raw-trials.jsonl")
    configurations = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (run_dir / "system-configurations").glob("*.json")
    }
    requirements = {}
    for path in (run_dir / "attack-definitions").glob("*.yaml"):
        attack = yaml.safe_load(path.read_text(encoding="utf-8"))
        requirements[str(attack["id"])] = list(attack.get("requires_capabilities") or [])

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / f"{run_dir.name}-non-pass-review.jsonl"
    selected = [record for record in records if record["status"] != "PASS"]
    selected.sort(key=lambda item: (item["system"], item["attack_id"], int(item["trial_n"])))
    with jsonl_path.open("w", encoding="utf-8") as stream:
        for record in selected:
            system = record["system"]
            attack = record["attack_id"]
            configuration = configurations[system]
            item = {
                "run_id": record["run_id"],
                "system": system,
                "attack_id": attack,
                "trial_n": int(record["trial_n"]),
                "status": record["status"],
                "evidence_file": f"failures/{system}-{attack}-{int(record['trial_n']):04d}.json",
                "requires_capabilities": requirements[attack],
                "declared_capabilities": configuration.get("capabilities") or [],
                "missing_capabilities": record.get("missing_capabilities") or [],
                "adapter_mapping_note": configuration.get("mapping_note"),
                "adapter_native_surfaces": NATIVE_SURFACES.get(system, {}),
                "classification_reason": classification_reason(record, configuration),
                "assertions_evaluated": len(record.get("assertions") or []),
            }
            stream.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")

    counts = Counter((item["system"], item["attack_id"], item["status"]) for item in selected)
    index = {
        "run_id": records[0]["run_id"],
        "purpose": "human review only; no comparative conclusion",
        "outside_evidence_package": True,
        "raw_trials_sha256": sha256(run_dir / "raw-trials.jsonl"),
        "benchmark_manifest_sha256": sha256(run_dir / "benchmark-manifest.json"),
        "non_pass_record_count": len(selected),
        "review_jsonl": jsonl_path.name,
        "review_jsonl_sha256": sha256(jsonl_path),
        "counts": [
            {"system": system, "attack_id": attack, "status": status, "count": count}
            for (system, attack, status), count in sorted(counts.items())
        ],
    }
    index_path = output_dir / f"{run_dir.name}-non-pass-index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return jsonl_path, index_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    paths = build_review(args.run_dir.resolve(), args.output_dir.resolve())
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
