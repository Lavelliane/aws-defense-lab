import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "threat-intel" / "import_indicators.py"
SPEC = importlib.util.spec_from_file_location("import_indicators", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IndicatorError = MODULE.IndicatorError
import_indicators = MODULE.import_indicators


class IndicatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "indicators.json"
        self.output = self.root / "ioc.cdb"

    def write(self, records):
        self.source.write_text(json.dumps(records))

    def test_invalid_ip_is_rejected_without_touching_output(self):
        self.output.write_text("existing:value\n")
        self.write([{"ip": "999.1.1.1", "source": "synthetic", "description": "bad",
                     "expires_at": "2099-01-01T00:00:00Z"}])
        with self.assertRaises(IndicatorError):
            import_indicators(self.source, self.output)
        self.assertEqual("existing:value\n", self.output.read_text())

    def test_expired_indicator_is_removed_from_refreshed_output(self):
        self.output.write_text("192.0.2.4:synthetic - expired\n")
        self.write([
            {"ip": "192.0.2.4", "source": "synthetic", "description": "expired",
             "expires_at": "2020-01-01T00:00:00Z"},
            {"ip": "192.0.2.5", "source": "synthetic", "description": "active",
             "expires_at": "2099-01-01T00:00:00Z"},
        ])
        self.assertTrue(import_indicators(self.source, self.output))
        self.assertEqual("192.0.2.5:synthetic - active\n", self.output.read_text())

    def test_ipv6_is_rejected_for_wazuh_address_match_key(self):
        self.write([{"ip": "2001:db8::1", "source": "synthetic", "description": "demo",
                     "expires_at": "2099-01-01T00:00:00Z"}])
        with self.assertRaisesRegex(IndicatorError, "IPv4"):
            import_indicators(self.source, self.output)

    def test_duplicate_ip_is_rejected(self):
        expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        row = {"ip": "192.0.2.4", "source": "synthetic", "description": "demo", "expires_at": expiry}
        self.write([row, row])
        with self.assertRaisesRegex(IndicatorError, "duplicate"):
            import_indicators(self.source, self.output)

    def test_atomic_text_output_and_change_signal(self):
        expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        self.write([{"ip": "192.0.2.4", "source": "synthetic", "description": "Demo IOC",
                     "expires_at": expiry}])
        self.assertTrue(import_indicators(self.source, self.output, add_lab_ip="10.0.1.7"))
        self.assertEqual(
            "10.0.1.7:synthetic lab manager IP\n192.0.2.4:synthetic - Demo IOC\n",
            self.output.read_text(),
        )
        self.assertFalse(import_indicators(self.source, self.output, add_lab_ip="10.0.1.7"))
        self.assertEqual([], list(self.root.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
