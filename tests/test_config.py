import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.config import load_target_config


class TargetConfigLoadingTests(unittest.TestCase):
    def test_loads_target_config_from_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "target.json"
            path.write_text(
                json.dumps(
                    {
                        "name": "DVWA Local",
                        "base_url": "http://127.0.0.1:4280",
                        "allowed_hosts": ["127.0.0.1"],
                        "allowed_schemes": ["http"],
                        "allowed_ports": [4280],
                        "enabled_modules": ["xss.reflected"],
                        "metadata": {"pinned_release": "2.5"},
                    }
                ),
                encoding="utf-8",
            )

            target = load_target_config(path)

            self.assertEqual(target.name, "DVWA Local")
            self.assertEqual(target.allowed_hosts, ["127.0.0.1"])
            self.assertEqual(target.allowed_ports, [4280])
            self.assertEqual(target.metadata["pinned_release"], "2.5")

    def test_rejects_missing_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "target.json"
            path.write_text("{}", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_target_config(path)


if __name__ == "__main__":
    unittest.main()
