from __future__ import annotations

import unittest

from adapters.llmbasedos_adapter import LLMBASEDOSAdapter, PINNED_COMMIT
from runner.run import execute_trial, load_attacks


class PinnedLLMBASEDOSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = LLMBASEDOSAdapter()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.adapter.close()

    def test_configuration_records_exact_target_and_enforce_mode(self) -> None:
        configuration = self.adapter.configuration()
        self.assertEqual(configuration["target_commit"], PINNED_COMMIT)
        self.assertEqual(configuration["integrity_mode"], "enforce")
        self.assertIn("working tree excluded", configuration["source_loading"])
        self.assertTrue(str(self.adapter._store_class.__module__).startswith("llmbasedos_src."))

    def test_one_seeded_trial_per_attack_passes(self) -> None:
        for attack in load_attacks(["A", "C", "D", "F", "H", "I", "L"]):
            with self.subTest(attack=attack["id"]):
                record = execute_trial(
                    self.adapter,
                    attack,
                    run_id="integration",
                    system="llmbasedos",
                    trial_n=1,
                    trial_seed=12345 + ord(attack["id"]),
                )
                self.assertEqual(record["status"], "PASS", record)


if __name__ == "__main__":
    unittest.main()
