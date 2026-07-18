import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dvwa_smoke import DEFAULT_CONFIG_PATH, DEFAULT_OUTPUT_ROOT, run_dvwa_smoke


class DvwaLikeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><title>DVWA</title></html>")

    def log_message(self, format: str, *args) -> None:
        return


class DvwaSmokeCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DvwaLikeHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_smoke_run_writes_auditable_artifacts_without_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "dvwa-local.json"
            config_path.write_text(
                json.dumps(
                    {
                        "name": "DVWA Test Double",
                        "base_url": f"http://127.0.0.1:{self.port}",
                        "allowed_hosts": ["127.0.0.1"],
                        "allowed_schemes": ["http"],
                        "allowed_ports": [self.port],
                        "enabled_modules": [
                            "xss.reflected",
                            "access.idor_read_only",
                            "sqli.boolean",
                        ],
                    }
                ),
                encoding="utf-8",
            )

            run_dir = run_dvwa_smoke(config_path, Path(tmp) / "runs")

            self.assertTrue((run_dir / "target.json").exists())
            self.assertEqual(len(list((run_dir / "actions").glob("*.json"))), 2)
            self.assertEqual(len(list((run_dir / "results").glob("*.json"))), 2)
            self.assertEqual(len(list((run_dir / "evidence").glob("*.json"))), 2)
            self.assertEqual(len(list((run_dir / "findings").glob("*.json"))), 0)
            self.assertIn("No findings", (run_dir / "report.md").read_text(encoding="utf-8"))

    def test_default_paths_are_repository_relative(self) -> None:
        self.assertTrue(DEFAULT_CONFIG_PATH.exists())
        self.assertEqual(DEFAULT_CONFIG_PATH.name, "dvwa-local.json")
        self.assertEqual(DEFAULT_OUTPUT_ROOT.name, ".adstf-runs")


if __name__ == "__main__":
    unittest.main()
