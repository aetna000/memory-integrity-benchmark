from __future__ import annotations

import tempfile
import unittest
import hashlib
import json
from pathlib import Path

from runner.sanitize_paths import file_inventory, replace_workspace_prefix
from runner.publication import validate_publication
from runner.run import ATTACK_ORDER


class PublicationSanitizationTests(unittest.TestCase):
    def _package(self, root: Path, *, dirty: bool = False, duplicate: bool = False) -> None:
        (root / "attack-definitions").mkdir()
        source_root = Path(__file__).resolve().parents[1] / "attacks"
        for source in source_root.glob("*.yaml"):
            (root / "attack-definitions" / source.name).write_bytes(source.read_bytes())
        (root / "system-configurations").mkdir()
        (root / "system-configurations" / "atmem.json").write_text("{}\n", encoding="utf-8")
        (root / "benchmark-manifest.json").write_text(
            json.dumps({"run_id": "unit", "harness_worktree_dirty_at_run": dirty}) + "\n",
            encoding="utf-8",
        )
        rows = []
        for attack in ATTACK_ORDER:
            rows.append(
                {
                    "run_id": "unit", "system": "atmem", "system_version": "2.3.5",
                    "attack_id": attack, "trial_n": 1, "seed": len(rows) + 1,
                    "inputs": {}, "observed_outputs": {}, "assertions": [],
                    "counter_delta": {}, "status": "NOT_REPRESENTABLE", "duration_ms": 0,
                }
            )
        if duplicate:
            rows[-1] = dict(rows[0])
        (root / "raw-trials.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
        )
        checksum_lines = []
        for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "SHA256SUMS"):
            checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
        (root / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    def test_valid_complete_clean_package_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._package(root)
            result = validate_publication(root, expected_trials=1)
            self.assertTrue(result["valid"])
            self.assertEqual(result["trial_count"], 7)

    def test_dirty_duplicate_invalid_status_secret_path_and_checksum_fail_closed(self) -> None:
        mutations = {
            "dirty": lambda root: self._package(root, dirty=True),
            "duplicate": lambda root: self._package(root, duplicate=True),
            "invalid_status": lambda root: (
                self._package(root),
                (root / "raw-trials.jsonl").write_text(
                    (root / "raw-trials.jsonl").read_text().replace("NOT_REPRESENTABLE", "BOGUS", 1),
                    encoding="utf-8",
                ),
            ),
            "secret": lambda root: (self._package(root), (root / "leak.txt").write_text("sk-proj-" + "A" * 48)),
            "path": lambda root: (self._package(root), (root / "leak.txt").write_text("/Users/example/private.db")),
            "checksum": lambda root: (self._package(root), (root / "benchmark-manifest.json").write_text("{}\n")),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                mutate(root)
                with self.assertRaises((ValueError, KeyError, json.JSONDecodeError)):
                    validate_publication(root, expected_trials=1)

    def test_inventory_allows_package_diff_as_derived_publication_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "raw-trials.jsonl").write_text("{}\n", encoding="utf-8")
            base_files = file_inventory(root)
            (root / "PACKAGE-DIFF.json").write_text("{}\n", encoding="utf-8")
            output_files = file_inventory(root)

            self.assertEqual(
                set(output_files),
                set(base_files) | {"PACKAGE-DIFF.json"},
            )

    def test_workspace_prefix_is_removed_without_changing_relative_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            path.write_text(
                '{"traceback":"/srv/private/benchmark/runner/run.py and '
                '/srv/private/benchmark/adapters/example.py"}\n',
                encoding="utf-8",
            )

            count, suffixes = replace_workspace_prefix(
                path,
                b"/srv/private/benchmark/",
            )

            self.assertEqual(count, 2)
            self.assertEqual(
                suffixes,
                {"runner/run.py": 1, "adapters/example.py": 1},
            )
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                '{"traceback":"runner/run.py and adapters/example.py"}\n',
            )


if __name__ == "__main__":
    unittest.main()
