from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from runner.sanitize_paths import replace_workspace_prefix


class PublicationSanitizationTests(unittest.TestCase):
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
