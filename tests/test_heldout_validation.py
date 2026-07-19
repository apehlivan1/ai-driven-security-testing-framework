import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.heldout_validation import DEFAULT_MANIFEST_PATH, validate_heldout_manifest


class HeldoutValidationTests(unittest.TestCase):
    def test_manifest_structure_is_valid_without_loading_ground_truth(self) -> None:
        result = validate_heldout_manifest(DEFAULT_MANIFEST_PATH)

        self.assertTrue(result["valid"])
        self.assertEqual(result["manifest_id"], "heldout-evaluation-manifest-v1")
        self.assertEqual(result["protocol_version"], "evaluation-protocol-v1")
        self.assertEqual(result["target_count"], 3)
        self.assertEqual(result["evaluation_unit_count"], 7)
        self.assertTrue(result["ground_truth_file_exists"])
        self.assertFalse(result["ground_truth_loaded"])

    def test_each_target_config_is_marked_held_out(self) -> None:
        result = validate_heldout_manifest(DEFAULT_MANIFEST_PATH)

        self.assertEqual(result["errors"], [])
        for target in result["target_results"]:
            self.assertTrue(target["valid"], target["errors"])
            self.assertGreater(target["max_actions"], 0)


if __name__ == "__main__":
    unittest.main()
