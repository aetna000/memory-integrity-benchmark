#!/usr/bin/env python3
"""Render the public four-system table from two raw evidence packages."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from runner.report import ATTACK_LABELS, ATTACK_ORDER, SYSTEM_LABELS, aggregate, read_trials


BEGIN_MARKER = "<!-- BEGIN GENERATED RESULTS -->"
END_MARKER = "<!-- END GENERATED RESULTS -->"
REPOSITORY_URL = "https://github.com/iluxu/memory-integrity-benchmark"
LLMBASEDOS_PACKAGE = "llmbasedos-v0.4-rc1-seed-20260801"
COMPETITOR_PACKAGE = "final-v4"
SYSTEM_ORDER = ["llmbasedos", "mem0", "zep", "letta"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_checksums(evidence_dir: Path) -> None:
    checksum_path = evidence_dir / "SHA256SUMS"
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        target = evidence_dir / relative
        if not target.is_file() or sha256(target) != expected:
            raise ValueError(f"checksum mismatch: {target}")


def normalize_aggregate_for_persisted_schema(result: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(result)
    if not normalized.get("metric_exclusions"):
        normalized.pop("metric_exclusions", None)
    return normalized


def load_evidence(evidence_dir: Path, expected_systems: list[str]) -> dict[str, Any]:
    verify_checksums(evidence_dir)
    records = read_trials(evidence_dir / "raw-trials.jsonl")
    result = aggregate(records)
    manifest = json.loads(
        (evidence_dir / "benchmark-manifest.json").read_text(encoding="utf-8")
    )
    persisted = json.loads(
        (evidence_dir / "aggregate-metrics.json").read_text(encoding="utf-8")
    )
    if result["systems"] != expected_systems:
        raise ValueError(
            f"unexpected systems in {evidence_dir}: {result['systems']}"
        )
    if result["attacks"] != ATTACK_ORDER:
        raise ValueError(f"unexpected attacks in {evidence_dir}: {result['attacks']}")
    if manifest.get("record_count") != len(records):
        raise ValueError(f"manifest record count mismatch in {evidence_dir}")
    if normalize_aggregate_for_persisted_schema(result) != persisted:
        raise ValueError(f"persisted metrics do not match raw counters in {evidence_dir}")
    return {"records": records, "result": result, "manifest": manifest}


def package_urls(package: str) -> dict[str, str]:
    base = f"{REPOSITORY_URL}/tree/main/results/published/{package}"
    blob = f"{REPOSITORY_URL}/blob/main/results/published/{package}"
    archive_name = (
        "final-v4.tar.gz"
        if package == COMPETITOR_PACKAGE
        else f"{LLMBASEDOS_PACKAGE}.tar.gz"
    )
    return {
        "package": f"{base}/evidence",
        "raw": f"{blob}/evidence/raw-trials.jsonl",
        "archive": f"{blob}/{archive_name}",
        "archive_sha256": f"{blob}/{archive_name}.sha256",
    }


def result_lookup(*results: dict[str, Any]) -> dict[tuple[str, str], str]:
    lookup: dict[tuple[str, str], str] = {}
    for result in results:
        for item in result["results"]:
            key = (item["system"], item["attack_id"])
            if key in lookup:
                raise ValueError(f"duplicate combined result cell: {key}")
            lookup[key] = item["status"]
    expected = {(system, attack) for system in SYSTEM_ORDER for attack in ATTACK_ORDER}
    if set(lookup) != expected:
        raise ValueError(
            f"combined result cells differ: missing={sorted(expected - set(lookup))}, "
            f"extra={sorted(set(lookup) - expected)}"
        )
    return lookup


def validate_factual_summary(
    lookup: dict[tuple[str, str], str], competitor_records: list[dict[str, Any]]
) -> None:
    if any(lookup[("llmbasedos", attack)] != "PASS" for attack in ATTACK_ORDER):
        raise ValueError("LLMBASEDOS summary no longer matches the raw result cells")
    for system in ("mem0", "letta"):
        if any(lookup[(system, attack)] != "PASS" for attack in ("C", "F", "L")):
            raise ValueError(f"{system} evaluable-cell summary no longer matches")
    not_representable_attacks = {
        attack
        for attack in ATTACK_ORDER
        if any(
            lookup[(system, attack)] == "NOT_REPRESENTABLE"
            for system in ("mem0", "zep", "letta")
        )
    }
    if not_representable_attacks != {"A", "D", "H", "I", "L"}:
        raise ValueError("NOT_REPRESENTABLE category summary no longer matches")
    if {lookup[("zep", attack)] for attack in ("C", "F")} != {"ERROR"}:
        raise ValueError("Zep ERROR summary no longer matches")
    zep_errors = {
        record.get("error", {}).get("message")
        for record in competitor_records
        if record["system"] == "zep" and record["status"] == "ERROR"
    }
    if zep_errors != {"Zep ingestion did not settle before the configured timeout"}:
        raise ValueError("Zep technical-error summary no longer matches")


def render_results_section(llmbasedos_dir: Path, competitor_dir: Path) -> str:
    llmbasedos = load_evidence(llmbasedos_dir, ["llmbasedos"])
    competitors = load_evidence(competitor_dir, ["mem0", "zep", "letta"])
    lookup = result_lookup(llmbasedos["result"], competitors["result"])
    validate_factual_summary(lookup, competitors["records"])

    llm_urls = package_urls(LLMBASEDOS_PACKAGE)
    competitor_urls = package_urls(COMPETITOR_PACKAGE)
    headers = [
        (
            f"[{SYSTEM_LABELS['llmbasedos']}<br><sub>{LLMBASEDOS_PACKAGE}</sub>]"
            f"({llm_urls['raw']})"
        ),
        f"[Mem0<br><sub>{COMPETITOR_PACKAGE}</sub>]({competitor_urls['raw']})",
        f"[Zep<br><sub>{COMPETITOR_PACKAGE}</sub>]({competitor_urls['raw']})",
        f"[Letta<br><sub>{COMPETITOR_PACKAGE}</sub>]({competitor_urls['raw']})",
    ]
    lines = [
        BEGIN_MARKER,
        "## Results",
        "",
        "<!-- Generated from both published raw-trials.jsonl files by "
        "runner/combined_report.py. Do not edit. -->",
        "",
        "| Attack | " + " | ".join(headers) + " |",
        "|---|" + "---|" * len(SYSTEM_ORDER),
    ]
    for attack in ATTACK_ORDER:
        statuses = [lookup[(system, attack)] for system in SYSTEM_ORDER]
        lines.append(f"| {ATTACK_LABELS[attack]} | " + " | ".join(statuses) + " |")
    lines.extend(
        [
            "",
            f"- Evidence: [LLMBASEDOS package]({llm_urls['package']}) "
            f"([raw trials]({llm_urls['raw']}), [archive]({llm_urls['archive']}), "
            f"[archive SHA-256]({llm_urls['archive_sha256']})).",
            f"- Evidence: [competitor final-v4 package]({competitor_urls['package']}) "
            f"([raw trials]({competitor_urls['raw']}), "
            f"[archive]({competitor_urls['archive']}), "
            f"[archive SHA-256]({competitor_urls['archive_sha256']})).",
            "",
            "LLMBASEDOS v0.4-rc1 has evaluable results in all seven categories; "
            "every cell is `PASS`.",
            "",
            "Mem0 and Letta have evaluable results in C, F, and L; every one of "
            "those cells is `PASS`.",
            "",
            "`NOT_REPRESENTABLE` appears in five categories. A, D, H, and I lack "
            "the tested native enforcement semantics in all three competitor "
            "adapters; Zep L used the frozen legacy capability gate, so no "
            "empirical Zep L trial was executed.",
            "",
            "Zep has no evaluable cell in this run. C and F are `ERROR` because "
            "episode ingestion did not settle within the configured 300-second "
            "timeout; A, D, H, I, and L are `NOT_REPRESENTABLE`. Its counter-derived "
            "metrics are therefore N/A.",
            END_MARKER,
        ]
    )
    return "\n".join(lines)


def replace_results_section(document: str, section: str) -> str:
    start = document.find(BEGIN_MARKER)
    end = document.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise ValueError("generated result markers are missing or malformed")
    end += len(END_MARKER)
    return document[:start] + section + document[end:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llmbasedos-evidence", required=True, type=Path)
    parser.add_argument("--competitor-evidence", required=True, type=Path)
    parser.add_argument("--write-document", action="append", default=[], type=Path)
    parser.add_argument("--check-document", action="append", default=[], type=Path)
    args = parser.parse_args()
    section = render_results_section(
        args.llmbasedos_evidence.resolve(), args.competitor_evidence.resolve()
    )
    for path in args.write_document:
        current = path.read_text(encoding="utf-8")
        path.write_text(replace_results_section(current, section), encoding="utf-8")
    for path in args.check_document:
        current = path.read_text(encoding="utf-8")
        if replace_results_section(current, section) != current:
            raise SystemExit(f"generated results are stale in {path}")
    if not args.write_document and not args.check_document:
        print(section)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
