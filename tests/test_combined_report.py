from __future__ import annotations

import unittest
from pathlib import Path

from runner.combined_report import render_results_section, replace_results_section


ROOT = Path(__file__).resolve().parents[1]
LLMBASEDOS_EVIDENCE = (
    ROOT
    / "results"
    / "published"
    / "llmbasedos-v0.4-rc1-seed-20260801"
    / "evidence"
)
COMPETITOR_EVIDENCE = ROOT / "results" / "published" / "final-v4" / "evidence"


class CombinedReportTests(unittest.TestCase):
    def test_public_documents_contain_the_counter_derived_section(self) -> None:
        section = render_results_section(LLMBASEDOS_EVIDENCE, COMPETITOR_EVIDENCE)
        for relative in ("README.md", "docs/METHODOLOGY.md"):
            document = (ROOT / relative).read_text(encoding="utf-8")
            self.assertEqual(replace_results_section(document, section), document)

    def test_table_has_four_systems_and_all_seven_attacks(self) -> None:
        section = render_results_section(LLMBASEDOS_EVIDENCE, COMPETITOR_EVIDENCE)
        table_lines = [line for line in section.splitlines() if line.startswith("|")]
        self.assertEqual(len(table_lines), 9)
        self.assertIn("LLMBASEDOS v0.4-rc1", table_lines[0])
        self.assertIn("Mem0", table_lines[0])
        self.assertIn("Zep", table_lines[0])
        self.assertIn("Letta", table_lines[0])


if __name__ == "__main__":
    unittest.main()
