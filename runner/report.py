#!/usr/bin/env python3
"""Aggregate only raw trial counters and produce a deterministic evidence table."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ATTACK_LABELS = {
    "A": "A — direct procedural poisoning",
    "C": "C — recursive agent hallucination",
    "D": "D — summary trust laundering",
    "F": "F — repetition → authority",
    "H": "H — outcome laundering",
    "I": "I — authorised promotion *(positive control)*",
    "L": "L — secret ingestion",
}
ATTACK_ORDER = list(ATTACK_LABELS)
SYSTEM_ORDER = ["llmbasedos", "mem0", "zep", "letta"]
SYSTEM_LABELS = {"llmbasedos": "LLMBASEDOS v0.4-rc1", "mem0": "Mem0", "zep": "Zep", "letta": "Letta"}
METRICS = {
    "taint_preservation_rate": ("preserved", "total_derivations"),
    "trust_laundering_rate": ("laundered", "total"),
    "secret_retention_rate": ("found_by_scan", "total_secrets"),
    "factual_contamination_rate": ("contaminated_recalls", "total_probes"),
}
EVALUABLE_STATUSES = frozenset({"PASS", "FAIL", "PARTIAL"})


def read_trials(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for line_n, line in enumerate(stream, start=1):
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSONL at line {line_n}: {error}") from error
    if not records:
        raise ValueError("raw-trials.jsonl is empty")
    return records


def pair_status(records: list[dict[str, Any]]) -> str:
    statuses = {record["status"] for record in records}
    if statuses == {"NOT_REPRESENTABLE"}:
        return "NOT_REPRESENTABLE"
    if statuses == {"NOT_SUPPORTED"}:
        return "NOT_SUPPORTED"
    if "ERROR" in statuses:
        return "ERROR"
    if statuses == {"PASS"}:
        return "PASS"
    if statuses == {"FAIL"}:
        return "FAIL"
    return "PARTIAL"


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    run_ids = {record["run_id"] for record in records}
    if len(run_ids) != 1:
        raise ValueError(f"raw file contains multiple run ids: {sorted(run_ids)}")
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    counters: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: {metric: {numerator: 0, denominator: 0} for metric, (numerator, denominator) in METRICS.items()}
    )
    metric_exclusions: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for record in records:
        grouped[(record["system"], record["attack_id"])].append(record)
        system_counters = counters[record["system"]]
        if record["status"] not in EVALUABLE_STATUSES:
            metric_exclusions[record["system"]][record["status"]] += 1
            continue
        for metric, (numerator, denominator) in METRICS.items():
            delta = record.get("counter_delta", {}).get(metric, {})
            system_counters[metric][numerator] += int(delta.get(numerator, 0))
            system_counters[metric][denominator] += int(delta.get(denominator, 0))
    results = []
    for (system, attack), items in sorted(grouped.items()):
        assertion_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"passed": 0, "total": 0})
        for item in items:
            for assertion in item["assertions"]:
                assertion_counts[assertion["kind"]]["total"] += 1
                assertion_counts[assertion["kind"]]["passed"] += int(assertion["pass"])
        results.append(
            {
                "system": system,
                "attack_id": attack,
                "status": pair_status(items),
                "trials": len(items),
                "trial_status_counts": {
                    status: sum(item["status"] == status for item in items)
                    for status in ["PASS", "FAIL", "PARTIAL", "NOT_REPRESENTABLE", "NOT_SUPPORTED", "ERROR"]
                    if any(item["status"] == status for item in items)
                },
                "assertion_counts": dict(assertion_counts),
            }
        )
    metrics: dict[str, Any] = {}
    for system, system_counters in counters.items():
        metrics[system] = {}
        for metric, (numerator, denominator) in METRICS.items():
            values = system_counters[metric]
            metrics[system][metric] = {
                numerator: values[numerator],
                denominator: values[denominator],
                "value": values[numerator] / values[denominator] if values[denominator] else None,
            }
    return {
        "run_id": next(iter(run_ids)),
        "systems": sorted({record["system"] for record in records}, key=lambda item: SYSTEM_ORDER.index(item)),
        "attacks": sorted({record["attack_id"] for record in records}, key=lambda item: ATTACK_ORDER.index(item)),
        "results": results,
        "metrics": metrics,
        "metric_exclusions": {
            system: dict(sorted(statuses.items()))
            for system, statuses in sorted(metric_exclusions.items())
        },
    }


def render_table(result: dict[str, Any], configurations: dict[str, dict[str, Any]]) -> str:
    systems = result["systems"]
    lookup = {(item["system"], item["attack_id"]): item for item in result["results"]}
    lines = [
        "<!-- Generated from raw-trials.jsonl by runner/report.py. Do not edit. -->",
        "",
        f"# Comparison — `{result['run_id']}`",
        "",
        "| Attack | " + " | ".join(SYSTEM_LABELS[item] for item in systems) + " |",
        "|---|" + "---|" * len(systems),
    ]
    for attack in result["attacks"]:
        cells = [lookup.get((system, attack), {}).get("status", "·") for system in systems]
        lines.append(f"| {ATTACK_LABELS[attack]} | " + " | ".join(cells) + " |")
    lines.extend(["", "## Native capability declarations", ""])
    for system in systems:
        config = configurations.get(system, {})
        capabilities = ", ".join(config.get("capabilities") or []) or "none"
        lines.append(f"- **{SYSTEM_LABELS[system]}:** `{capabilities}`")
        if config.get("mapping_note"):
            lines.append(f"  Mapping: {config['mapping_note']}")
    lines.extend([
        "",
        "## Counter-derived metrics",
        "",
        "Only assertion-bearing `PASS`/`FAIL`/`PARTIAL` trials contribute counters; "
        "`ERROR`, `NOT_REPRESENTABLE`, and `NOT_SUPPORTED` are excluded.",
        "",
    ])
    for system in systems:
        lines.append(f"### {SYSTEM_LABELS[system]}")
        lines.append("")
        for metric, (numerator, denominator) in METRICS.items():
            values = result["metrics"].get(system, {}).get(metric, {numerator: 0, denominator: 0, "value": None})
            rendered = "N/A" if values["value"] is None else f"{values['value']:.6f}"
            lines.append(f"- `{metric}`: {values[numerator]}/{values[denominator]} = {rendered}")
        exclusions = result.get("metric_exclusions", {}).get(system, {})
        rendered_exclusions = ", ".join(f"{status}={count}" for status, count in exclusions.items()) or "none"
        lines.append(f"- Excluded non-evaluable trials: {rendered_exclusions}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_failures(run_dir: Path, records: list[dict[str, Any]]) -> None:
    failures = run_dir / "failures"
    failures.mkdir(exist_ok=True)
    for old in failures.glob("*.json"):
        old.unlink()
    for record in records:
        if record["status"] != "PASS":
            path = failures / f"{record['system']}-{record['attack_id']}-{record['trial_n']:04d}.json"
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_checksums(run_dir: Path) -> None:
    entries = []
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file() and item.name != "SHA256SUMS"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(run_dir).as_posix()}")
    (run_dir / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")


def report(run_dir: Path) -> dict[str, Any]:
    records = read_trials(run_dir / "raw-trials.jsonl")
    result = aggregate(records)
    configurations = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (run_dir / "system-configurations").glob("*.json")
    }
    (run_dir / "aggregate-metrics.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / "generated-comparison-table.md").write_text(
        render_table(result, configurations), encoding="utf-8"
    )
    write_failures(run_dir, records)
    write_checksums(run_dir)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    result = report(args.run_dir.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
