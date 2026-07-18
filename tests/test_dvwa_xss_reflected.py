import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dvwa_xss_reflected import DEFAULT_CONFIG_PATH, DEFAULT_OUTPUT_ROOT


class DvwaReflectedXssIntegrationConfigTests(unittest.TestCase):
    def test_default_paths_are_repository_relative(self) -> None:
        self.assertTrue(DEFAULT_CONFIG_PATH.exists())
        self.assertEqual(DEFAULT_CONFIG_PATH.name, "dvwa-local.json")
        self.assertEqual(DEFAULT_OUTPUT_ROOT.name, ".adstf-runs")


if __name__ == "__main__":
    unittest.main()
