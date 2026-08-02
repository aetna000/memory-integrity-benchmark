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
ZEP_L_PACKAGE = "zep-L-empirical-seed-20260801"
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


def normalize_aggregate_for_persisted_schema(
    result: dict[str, Any], persisted: dict[str, Any]
) -> dict[str, Any]:
    normalized = dict(result)
    if "metric_exclusions" not in persisted and not normalized.get("metric_exclusions"):
        normalized.pop("metric_exclusions", None)
    return normalized


def load_evidence(
    evidence_dir: Path,
    expected_systems: list[str],
    expected_attacks: list[str] = ATTACK_ORDER,
) -> dict[str, Any]:
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
    if result["attacks"] != expected_attacks:
        raise ValueError(f"unexpected attacks in {evidence_dir}: {result['attacks']}")
    if manifest.get("record_count") != len(records):
        raise ValueError(f"manifest record count mismatch in {evidence_dir}")
    if normalize_aggregate_for_persisted_schema(result, persisted) != persisted:
        raise ValueError(f"persisted metrics do not match raw counters in {evidence_dir}")
    return {"records": records, "result": result, "manifest": manifest}


def package_urls(package: str) -> dict[str, str]:
    base = f"{REPOSITORY_URL}/tree/main/results/published/{package}"
    blob = f"{REPOSITORY_URL}/blob/main/results/published/{package}"
    archive_name = {
        COMPETITOR_PACKAGE: "final-v4.tar.gz",
        LLMBASEDOS_PACKAGE: f"{LLMBASEDOS_PACKAGE}.tar.gz",
        ZEP_L_PACKAGE: f"{ZEP_L_PACKAGE}.tar.gz",
    }[package]
    return {
        "package": f"{base}/evidence",
        "raw": f"{blob}/evidence/raw-trials.jsonl",
        "archive": f"{blob}/{archive_name}",
        "archive_sha256": f"{blob}/{archive_name}.sha256",
    }


def result_lookup(
    llmbasedos_result: dict[str, Any],
    competitor_result: dict[str, Any],
    zep_l_result: dict[str, Any],
) -> dict[tuple[str, str], str]:
    lookup: dict[tuple[str, str], str] = {}
    for result in (llmbasedos_result, competitor_result):
        for item in result["results"]:
            key = (item["system"], item["attack_id"])
            if key in lookup:
                raise ValueError(f"duplicate combined result cell: {key}")
            lookup[key] = item["status"]
    zep_l_rows = zep_l_result["results"]
    if len(zep_l_rows) != 1 or (
        zep_l_rows[0]["system"], zep_l_rows[0]["attack_id"]
    ) != ("zep", "L"):
        raise ValueError("the Zep L override package must contain exactly Zep × L")
    lookup[("zep", "L")] = zep_l_rows[0]["status"]
    expected = {(system, attack) for system in SYSTEM_ORDER for attack in ATTACK_ORDER}
    if set(lookup) != expected:
        raise ValueError(
            f"combined result cells differ: missing={sorted(expected - set(lookup))}, "
            f"extra={sorted(set(lookup) - expected)}"
        )
    return lookup


def validate_factual_summary(
    lookup: dict[tuple[str, str], str],
    competitor_records: list[dict[str, Any]],
    zep_l_records: list[dict[str, Any]],
) -> None:
    if any(lookup[("llmbasedos", attack)] != "PASS" for attack in ATTACK_ORDER):
        raise ValueError("LLMBASEDOS summary no longer matches the raw result cells")
    for system in ("mem0", "letta"):
        if any(lookup[(system, attack)] != "PASS" for attack in ("C", "F", "L")):
            raise ValueError(f"{system} evaluable-cell summary no longer matches")
    if lookup[("zep", "L")] != "PASS":
        raise ValueError("Zep L empirical summary no longer matches")
    not_representable_attacks = {
        attack
        for attack in ATTACK_ORDER
        if any(
            lookup[(system, attack)] == "NOT_REPRESENTABLE"
            for system in ("mem0", "zep", "letta")
        )
    }
    if not_representable_attacks != {"A", "D", "H", "I"}:
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
    if len(zep_l_records) != 100 or {row["status"] for row in zep_l_records} != {"PASS"}:
        raise ValueError("Zep L trial-count or status summary no longer matches")
    found = sum(
        row["counter_delta"]["secret_retention_rate"]["found_by_scan"]
        for row in zep_l_records
    )
    total = sum(
        row["counter_delta"]["secret_retention_rate"]["total_secrets"]
        for row in zep_l_records
    )
    if (found, total) != (0, 100):
        raise ValueError("Zep L secret-retention summary no longer matches")


def render_results_section(
    llmbasedos_dir: Path, competitor_dir: Path, zep_l_dir: Path
) -> str:
    llmbasedos = load_evidence(llmbasedos_dir, ["llmbasedos"])
    competitors = load_evidence(competitor_dir, ["mem0", "zep", "letta"])
    zep_l = load_evidence(zep_l_dir, ["zep"], ["L"])
    lookup = result_lookup(
        llmbasedos["result"], competitors["result"], zep_l["result"]
    )
    validate_factual_summary(lookup, competitors["records"], zep_l["records"])

    llm_urls = package_urls(LLMBASEDOS_PACKAGE)
    competitor_urls = package_urls(COMPETITOR_PACKAGE)
    zep_l_urls = package_urls(ZEP_L_PACKAGE)
    headers = [
        (
            f"[{SYSTEM_LABELS['llmbasedos']}<br><sub>{LLMBASEDOS_PACKAGE}</sub>]"
            f"({llm_urls['raw']})"
        ),
        f"[Mem0<br><sub>{COMPETITOR_PACKAGE}</sub>]({competitor_urls['raw']})",
        "Zep<br><sub>"
        f"[{COMPETITOR_PACKAGE}]({competitor_urls['raw']}) + "
        f"[{ZEP_L_PACKAGE}]({zep_l_urls['raw']})</sub>",
        f"[Letta<br><sub>{COMPETITOR_PACKAGE}</sub>]({competitor_urls['raw']})",
    ]
    lines = [
        BEGIN_MARKER,
        "## Results",
        "",
        "<!-- Generated from three published raw-trials.jsonl files by "
        "runner/combined_report.py. Do not edit. -->",
        "",
        "| Attack | " + " | ".join(headers) + " |",
        "|---|" + "---|" * len(SYSTEM_ORDER),
    ]
    for attack in ATTACK_ORDER:
        statuses = []
        for system in SYSTEM_ORDER:
            status = lookup[(system, attack)]
            if (system, attack) == ("zep", "L"):
                status = f"[{status}]({zep_l_urls['raw']})"
            statuses.append(status)
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
            f"- Evidence: [Zep L empirical package]({zep_l_urls['package']}) "
            f"([raw trials]({zep_l_urls['raw']}), [archive]({zep_l_urls['archive']}), "
            f"[archive SHA-256]({zep_l_urls['archive_sha256']})).",
            "",
            "LLMBASEDOS v0.4-rc1 has evaluable results in all seven categories; "
            "every cell is `PASS`.",
            "",
            "Mem0 and Letta have evaluable results in C, F, and L; every one of "
            "those cells is `PASS`. Zep L is separately evaluable and is `PASS`.",
            "",
            "`NOT_REPRESENTABLE` appears in four categories: A, D, H, and I. The "
            "three competitor adapters lack the tested native enforcement semantics "
            "for those categories.",
            "",
            "Zep C and F remain `ERROR` because "
            "episode ingestion did not settle within the configured 300-second "
            "timeout. The separate empirical L run completed 100 trials with "
            "secret retention observed in 0/100 trials.",
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
    parser.add_argument("--zep-l-evidence", required=True, type=Path)
    parser.add_argument("--write-document", action="append", default=[], type=Path)
    parser.add_argument("--check-document", action="append", default=[], type=Path)
    args = parser.parse_args()
    section = render_results_section(
        args.llmbasedos_evidence.resolve(),
        args.competitor_evidence.resolve(),
        args.zep_l_evidence.resolve(),
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
