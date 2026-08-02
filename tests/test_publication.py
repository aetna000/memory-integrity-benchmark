from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from runner.sanitize_paths import file_inventory, replace_workspace_prefix


class PublicationSanitizationTests(unittest.TestCase):
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
