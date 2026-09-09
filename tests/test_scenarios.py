import json
import unittest
from unittest.mock import patch

from scenarios.run import ScenarioError, run_scenario, validate_target


class FakeResponse:
    def __init__(self, status, payload=b"", url="http://10.0.0.5:8080/health"):
        self.status = status
        self._payload = payload
        self._url = url

    def read(self, limit=-1):
        return self._payload[:limit] if limit >= 0 else self._payload

    def geturl(self):
        return self._url

    def close(self):
        pass

    def __enter__(self): return self
    def __exit__(self, *args): return False


class ScenarioTests(unittest.TestCase):
    def test_target_rejects_credentials_query_and_non_http(self):
        for target in (
            "https://user:pass@10.0.0.5:8080",
            "http://10.0.0.5:8080/?x=1",
            "file:///tmp/demo",
        ):
            with self.subTest(target=target), self.assertRaises(ScenarioError):
                validate_target(target)

    def test_health_guard_rejects_wrong_lab(self):
        bad = FakeResponse(200, json.dumps({"lab_id": "other", "mode": "vulnerable"}).encode())
        with patch("scenarios.run.urlopen", return_value=bad):
            with self.assertRaisesRegex(ScenarioError, "identity"):
                run_scenario("http://10.0.0.5:8080", "probe", "run-1")

    def test_health_guard_rejects_non_object_json(self):
        bad = FakeResponse(200, b"[]")
        with patch("scenarios.run.urlopen", return_value=bad):
            with self.assertRaisesRegex(ScenarioError, "identity"):
                run_scenario("http://10.0.0.5:8080", "probe", "run-1")

    def test_redirect_is_refused(self):
        redirected = FakeResponse(200, b"{}", "http://example.com/health")
        with patch("scenarios.run.urlopen", return_value=redirected):
            with self.assertRaisesRegex(ScenarioError, "redirect"):
                run_scenario("http://10.0.0.5:8080", "probe", "run-1")

    def test_refused_redirect_status_is_reported_as_redirect(self):
        response = FakeResponse(302, b"", "http://10.0.0.5:8080/health")
        with patch("scenarios.run.urlopen", return_value=response):
            with self.assertRaisesRegex(ScenarioError, "redirect"):
                run_scenario("http://10.0.0.5:8080", "probe", "run-1")

    def test_export_scenarios_require_expected_permission(self):
        for scenario, mode, export_status in (("exploit", "vulnerable", 200),
                                              ("verify", "hardened", 403)):
            payload = json.dumps({"lab_id": "aws-defense-lab", "mode": mode}).encode()
            health = FakeResponse(200, payload)
            export_url = "http://10.0.0.5:8080/export?key=restricted%2Ffinance.csv&run_id=run-1"
            export = FakeResponse(export_status, b"", export_url)
            with self.subTest(scenario=scenario), patch(
                "scenarios.run.urlopen", side_effect=[health, export]
            ):
                result = run_scenario("http://10.0.0.5:8080", scenario, "run-1")
                self.assertEqual(export_status, result["status"])
                self.assertEqual("run-1", result["run_id"])

    def test_export_scenario_rejects_wrong_application_mode_before_export(self):
        for scenario, mode in (("exploit", "hardened"), ("verify", "vulnerable")):
            health = FakeResponse(200, json.dumps({"lab_id": "aws-defense-lab", "mode": mode}).encode())
            with self.subTest(scenario=scenario), patch(
                "scenarios.run.urlopen", return_value=health
            ) as opened:
                with self.assertRaisesRegex(ScenarioError, "mode"):
                    run_scenario("http://10.0.0.5:8080", scenario, "run-1")
                self.assertEqual(1, opened.call_count)

    def test_probe_is_bounded_to_five_requests_after_health(self):
        health = FakeResponse(200, b'{"lab_id":"aws-defense-lab","mode":"vulnerable"}')
        probes = [FakeResponse(404, b"not found", f"http://10.0.0.5:8080{path}?run_id=run-1")
                  for path in ("/admin", "/login", "/.env", "/debug", "/backup")]
        with patch("scenarios.run.urlopen", side_effect=[health] + probes) as opened:
            result = run_scenario("http://10.0.0.5:8080", "probe", "run-1")
        self.assertEqual(5, result["requests"])
        self.assertEqual(6, opened.call_count)


if __name__ == "__main__":
    unittest.main()
