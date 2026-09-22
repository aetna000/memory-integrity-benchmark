from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jsonschema
import yaml

from adapters.base import call_with_retry
from runner import report as report_module
from runner.environment import credential_status, load_benchmark_environment
from runner.merge import merge_shards
from runner.run import (
    ATTACK_ORDER,
    ROOT,
    derive_seed,
    load_attacks,
    load_schema,
    variation_values,
    counter_delta,
    evaluate_assertion,
    run,
    SYSTEM_CAPABILITIES,
    SYSTEM_ORDER,
)


class DeclarativeContractTests(unittest.TestCase):
    def test_atmem_is_registered_without_changing_existing_order(self) -> None:
        self.assertEqual(SYSTEM_ORDER, ["llmbasedos", "atmem", "mem0", "zep", "letta"])
        self.assertEqual(SYSTEM_CAPABILITIES["atmem"], {"source_trust", "procedural_memory"})

    def test_all_seven_attacks_validate_and_are_code_free(self) -> None:
        attacks = load_attacks(ATTACK_ORDER)
        self.assertEqual([item["id"] for item in attacks], ATTACK_ORDER)
        schema = load_schema("attack.schema.json")
        for attack in attacks:
            raw = yaml.safe_load(attack["_path"].read_text(encoding="utf-8"))
            jsonschema.validate(raw, schema)
            self.assertNotIn("python", raw)
            self.assertTrue(raw["variation"]["seeded"])

    def test_secret_attack_is_empirical_and_ingests_the_secret(self) -> None:
        attack = load_attacks(["L"])[0]
        self.assertEqual(attack["requires_capabilities"], [])
        self.assertIn("{{secret}}", attack["steps"][0]["content"])

    def test_trial_seed_is_system_independent_and_varies_by_trial(self) -> None:
        first = derive_seed(17, "D", 1)
        self.assertEqual(first, derive_seed(17, "D", 1))
        self.assertNotEqual(first, derive_seed(17, "D", 2))
        self.assertNotEqual(first, derive_seed(17, "C", 1))
        values = variation_values(first)
        self.assertRegex(values["principal"], r"^p-[0-9a-f]{12}$")
        self.assertRegex(values["secret"], r"^sk-proj-[A-Z0-9]{48}$")

    def test_llmbasedos_pin_is_literal_and_not_head(self) -> None:
        source = (ROOT / "adapters" / "llmbasedos_adapter.py").read_text(encoding="utf-8")
        self.assertIn('PINNED_TAG = "v0.4-rc1"', source)
        self.assertIn('PINNED_COMMIT = "54a1dda4c896c2e7697c4849e1025d726bb29519"', source)
        self.assertIn('"archive", "--format=tar", PINNED_COMMIT', source)

    def test_only_real_derivations_enter_derivation_denominator(self) -> None:
        assertion = [{"kind": "taint_preserved", "pass": True}]
        self.assertEqual(
            counter_delta("D", assertion)["taint_preservation_rate"],
            {"preserved": 1, "total_derivations": 1},
        )
        self.assertEqual(
            counter_delta("H", assertion)["taint_preservation_rate"],
            {"preserved": 0, "total_derivations": 0},
        )
        self.assertEqual(
            counter_delta("F", [])["trust_laundering_rate"],
            {"laundered": 0, "total": 0},
        )

    def test_example_environment_contains_only_expected_names(self) -> None:
        content = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("MEM0_API_KEY=", content)
        self.assertIn("ZEP_API_KEY=", content)
        self.assertIn("LETTA_API_KEY=", content)
        self.assertNotRegex(content, r"sk-[A-Za-z0-9]{16,}")

    def test_each_competitor_has_a_sourced_six_capability_review(self) -> None:
        capabilities = {
            "source_trust", "derivation_tracking", "procedural_memory",
            "authority_gating", "purpose_scoped_recall", "secret_blocking",
        }
        for system in ("atmem", "mem0", "zep", "letta"):
            content = (ROOT / "adapters" / system / "CAPABILITIES.md").read_text(encoding="utf-8")
            for capability in capabilities:
                self.assertRegex(
                    content,
                    rf"\| `{capability}` \| `(PRESENT|ABSENT|STORABLE_WITHOUT_SEMANTICS)` \| .*https://",
                )
            self.assertGreaterEqual(content.count("https://"), 6)

    def test_readme_contains_normative_not_representable_definition(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            content,
            r"the system's data model\s+attaches no native enforcement semantics",
        )

    def test_env_file_never_overrides_process_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env_path = Path(temporary) / ".env"
            env_path.write_text("MEM0_API_KEY=file-value\nZEP_API_KEY=zep-value\n", encoding="utf-8")
            with patch.dict(os.environ, {"MEM0_API_KEY": "process-value"}, clear=True):
                self.assertTrue(load_benchmark_environment(env_path))
                self.assertEqual(os.environ["MEM0_API_KEY"], "process-value")
                self.assertEqual(os.environ["ZEP_API_KEY"], "zep-value")
                status = credential_status()
                self.assertTrue(status["mem0"]["configured"])
                self.assertTrue(status["zep"]["configured"])
                self.assertFalse(status["letta"]["configured"])

    def test_blank_placeholders_are_absent_and_letta_cloud_requires_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env_path = Path(temporary) / ".env"
            env_path.write_text(
                "MEM0_API_KEY=   \nLETTA_API_KEY=\nLETTA_BASE_URL=https://api.letta.com\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                load_benchmark_environment(env_path)
                self.assertNotIn("MEM0_API_KEY", os.environ)
                self.assertNotIn("LETTA_API_KEY", os.environ)
                status = credential_status()
                self.assertFalse(status["letta"]["configured"])
                self.assertTrue(status["letta"]["cloud_endpoint_requires_key"])

    def test_transient_api_errors_retry_but_client_errors_do_not(self) -> None:
        class ApiError(Exception):
            def __init__(self, status_code: int):
                self.status_code = status_code
                super().__init__(f"HTTP {status_code}")

        attempts = {"count": 0}

        def eventually_succeeds() -> str:
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise ApiError(503)
            return "ok"

        self.assertEqual(
            call_with_retry(eventually_succeeds, attempts=3, base_delay_seconds=0),
            "ok",
        )
        self.assertEqual(attempts["count"], 3)

        attempts["count"] = 0

        def bad_request() -> None:
            attempts["count"] += 1
            raise ApiError(400)

        with self.assertRaises(ApiError):
            call_with_retry(bad_request, attempts=5, base_delay_seconds=0)
        self.assertEqual(attempts["count"], 1)

    def test_rate_limit_retry_honors_numeric_retry_after(self) -> None:
        class ApiError(Exception):
            status_code = 429
            headers = {"retry-after": "59"}

        attempts = {"count": 0}

        def operation() -> str:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise ApiError("rate limited")
            return "ok"

        with patch("adapters.base.time.sleep") as sleep:
            self.assertEqual(call_with_retry(operation), "ok")
        sleep.assert_called_once_with(59.0)


def raw_record(system: str, attack: str, status: str, delta: dict) -> dict:
    return {
        "run_id": "unit-run",
        "system": system,
        "system_version": "unit",
        "attack_id": attack,
        "trial_n": 1,
        "seed": 7,
        "inputs": {},
        "observed_outputs": {},
        "assertions": [{"kind": "unit", "expected": True, "actual": status == "PASS", "pass": status == "PASS"}],
        "counter_delta": delta,
        "status": status,
        "duration_ms": 1,
    }


class AggregationTests(unittest.TestCase):
    def test_secret_assertion_uses_observed_scan_not_handle_existence(self) -> None:
        class NoInspectionAdapter:
            def inspect(self, memory_id: str) -> dict:
                raise AssertionError("secret assertion must not infer storage from a harness handle")

        passed = evaluate_assertion(
            NoInspectionAdapter(),
            {"kind": "secret_not_retained", "target": "step_1_output", "probe": 1},
            {"step_1_output": "handle"},
            [{"retained": False, "channels": {"search": False}}],
            {"secret": "synthetic"},
        )
        failed = evaluate_assertion(
            NoInspectionAdapter(),
            {"kind": "secret_not_retained", "target": "step_1_output", "probe": 1},
            {"step_1_output": "handle"},
            [{"retained": True, "channels": {"search": True}}],
            {"secret": "synthetic"},
        )
        self.assertTrue(passed["pass"])
        self.assertFalse(failed["pass"])

    def test_secret_assertion_rejects_raw_transcript_as_a_scoring_channel(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot score secret retention"):
            evaluate_assertion(
                object(),
                {"kind": "secret_not_retained", "target": "step_1_output", "probe": 1},
                {"step_1_output": "handle"},
                [{"retained": True, "channels": {"agent_message_history": True}}],
                {"secret": "synthetic"},
            )

    def test_secret_assertion_is_derived_from_scoring_channels(self) -> None:
        with self.assertRaisesRegex(ValueError, "disagrees with its scoring channels"):
            evaluate_assertion(
                object(),
                {"kind": "secret_not_retained", "target": "step_1_output", "probe": 1},
                {"step_1_output": "handle"},
                [{"retained": True, "channels": {"messages_search": False}}],
                {"secret": "synthetic"},
            )

    def test_runner_executes_only_requested_one_based_trial_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "range"
            run(SimpleNamespace(
                systems="mem0",
                attacks="A",
                trials_from_yaml=True,
                trials=1,
                seed=17,
                run_id="unit-range",
                output_dir=output,
                trial_start=3,
                trial_end=4,
            ))
            records = report_module.read_trials(output / "raw-trials.jsonl")
            self.assertEqual([record["trial_n"] for record in records], [3, 4])
            self.assertTrue(all(record["status"] == "NOT_REPRESENTABLE" for record in records))

    def test_metrics_come_only_from_trial_counter_deltas(self) -> None:
        delta = {
            "taint_preservation_rate": {"preserved": 3, "total_derivations": 4},
            "trust_laundering_rate": {"laundered": 1, "total": 5},
            "secret_retention_rate": {"found_by_scan": 0, "total_secrets": 2},
            "factual_contamination_rate": {"contaminated_recalls": 2, "total_probes": 10},
        }
        result = report_module.aggregate([raw_record("llmbasedos", "D", "PASS", delta)])
        metrics = result["metrics"]["llmbasedos"]
        self.assertEqual(metrics["taint_preservation_rate"]["value"], 0.75)
        self.assertEqual(metrics["trust_laundering_rate"]["value"], 0.2)
        self.assertEqual(metrics["secret_retention_rate"]["value"], 0.0)
        self.assertEqual(metrics["factual_contamination_rate"]["value"], 0.2)

    def test_not_representable_is_not_failure(self) -> None:
        record = raw_record("mem0", "A", "NOT_REPRESENTABLE", {})
        result = report_module.aggregate([record])
        self.assertEqual(result["results"][0]["status"], "NOT_REPRESENTABLE")

    def test_non_evaluable_trials_never_enter_metric_counters(self) -> None:
        legacy_delta = {
            "taint_preservation_rate": {"preserved": 1, "total_derivations": 1},
            "trust_laundering_rate": {"laundered": 0, "total": 1},
            "secret_retention_rate": {"found_by_scan": 1, "total_secrets": 1},
            "factual_contamination_rate": {"contaminated_recalls": 0, "total_probes": 1},
        }
        result = report_module.aggregate([raw_record("zep", "F", "ERROR", legacy_delta)])
        metrics = result["metrics"]["zep"]
        self.assertTrue(all(value["value"] is None for value in metrics.values()))
        self.assertTrue(all(sum(number for key, number in value.items() if key != "value") == 0 for value in metrics.values()))
        self.assertEqual(result["metric_exclusions"], {"zep": {"ERROR": 1}})

    def test_report_is_bit_for_bit_reproducible(self) -> None:
        delta = {
            "taint_preservation_rate": {"preserved": 0, "total_derivations": 0},
            "trust_laundering_rate": {"laundered": 0, "total": 0},
            "secret_retention_rate": {"found_by_scan": 0, "total_secrets": 0},
            "factual_contamination_rate": {"contaminated_recalls": 0, "total_probes": 1},
        }
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "system-configurations").mkdir()
            (run_dir / "system-configurations" / "llmbasedos.json").write_text(
                json.dumps({"capabilities": []}), encoding="utf-8"
            )
            (run_dir / "raw-trials.jsonl").write_text(
                json.dumps(raw_record("llmbasedos", "C", "PASS", delta), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report_module.report(run_dir)
            first = (run_dir / "generated-comparison-table.md").read_bytes()
            metrics = (run_dir / "aggregate-metrics.json").read_bytes()
            report_module.report(run_dir)
            self.assertEqual(first, (run_dir / "generated-comparison-table.md").read_bytes())
            self.assertEqual(metrics, (run_dir / "aggregate-metrics.json").read_bytes())

    def test_shard_merge_refuses_missing_trials_and_never_synthesizes(self) -> None:
        delta = {
            "taint_preservation_rate": {"preserved": 0, "total_derivations": 0},
            "trust_laundering_rate": {"laundered": 0, "total": 0},
            "secret_retention_rate": {"found_by_scan": 0, "total_secrets": 0},
            "factual_contamination_rate": {"contaminated_recalls": 0, "total_probes": 1},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def shard(system: str) -> Path:
                path = root / system
                (path / "system-configurations").mkdir(parents=True)
                (path / "attack-definitions").mkdir()
                manifest = {
                    "run_id": "unit-run",
                    "seed": 7,
                    "harness_commit": "a" * 40,
                    "harness_worktree_dirty_at_run": False,
                    "environment": {},
                }
                (path / "benchmark-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                (path / "raw-trials.jsonl").write_text(
                    json.dumps(raw_record(system, "C", "PASS", delta)) + "\n", encoding="utf-8"
                )
                (path / "system-configurations" / f"{system}.json").write_text(
                    json.dumps({"name": system, "version": "unit", "capabilities": []}),
                    encoding="utf-8",
                )
                (path / "attack-definitions" / "C.yaml").write_text("id: C\n", encoding="utf-8")
                (path / "environment.lock").write_text("unit==1\n", encoding="utf-8")
                return path

            mem0 = shard("mem0")
            zep = shard("zep")
            output = root / "merged"
            merge_shards(
                [mem0, zep], output,
                required_systems=["mem0", "zep"], required_attacks=["C"], required_trials=1,
            )
            records = report_module.read_trials(output / "raw-trials.jsonl")
            self.assertEqual(len(records), 2)
            self.assertEqual({item["system"] for item in records}, {"mem0", "zep"})
            with self.assertRaises(ValueError):
                merge_shards(
                    [mem0], root / "incomplete",
                    required_systems=["mem0", "zep"], required_attacks=["C"], required_trials=1,
                )

    def test_shard_merge_records_distinct_clean_harness_commits(self) -> None:
        delta = {
            "taint_preservation_rate": {"preserved": 0, "total_derivations": 0},
            "trust_laundering_rate": {"laundered": 0, "total": 0},
            "secret_retention_rate": {"found_by_scan": 0, "total_secrets": 0},
            "factual_contamination_rate": {"contaminated_recalls": 0, "total_probes": 1},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def shard(system: str, revision: str) -> Path:
                path = root / system
                (path / "system-configurations").mkdir(parents=True)
                (path / "attack-definitions").mkdir()
                (path / "benchmark-manifest.json").write_text(
                    json.dumps({
                        "run_id": "unit-run", "seed": 7, "harness_commit": revision,
                        "harness_worktree_dirty_at_run": False, "environment": {},
                    }),
                    encoding="utf-8",
                )
                (path / "raw-trials.jsonl").write_text(
                    json.dumps(raw_record(system, "C", "PASS", delta)) + "\n", encoding="utf-8"
                )
                (path / "system-configurations" / f"{system}.json").write_text(
                    json.dumps({"name": system, "version": "unit", "capabilities": []}),
                    encoding="utf-8",
                )
                (path / "attack-definitions" / "C.yaml").write_text("id: C\n", encoding="utf-8")
                (path / "environment.lock").write_text("unit==1\n", encoding="utf-8")
                return path

            output = root / "merged"
            merge_shards(
                [shard("mem0", "a" * 40), shard("zep", "b" * 40)], output,
                required_systems=["mem0", "zep"], required_attacks=["C"], required_trials=1,
            )
            manifest = json.loads((output / "benchmark-manifest.json").read_text(encoding="utf-8"))
            self.assertIsNone(manifest["harness_commit"])
            self.assertEqual(manifest["harness_commits"], ["a" * 40, "b" * 40])
            self.assertEqual(
                {item["directory"]: item["harness_commit"] for item in manifest["merged_shards"]},
                {"mem0": "a" * 40, "zep": "b" * 40},
            )
            self.assertRegex(manifest["merge_report_commit"], r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
