import json
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

from app.server import ExportApplication, S3Store, make_handler


class FakeStore:
    def __init__(self):
        self.keys = {
            "public/report.csv": b"month,total\nJan,100\n",
            "restricted/finance.csv": b"account,balance\nDemo,999\n",
        }
        self.requests = []

    def get(self, key):
        self.requests.append(key)
        return self.keys[key], "s3-demo-request"


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "app.jsonl"
        self.store = FakeStore()

    def app(self, mode="vulnerable"):
        return ExportApplication(mode, self.store, self.log)

    def test_health_identifies_lab_and_mode(self):
        response = self.app().handle("GET", "/health", "10.0.0.8", {})
        self.assertEqual(200, response.status)
        self.assertEqual(
            {"lab_id": "aws-defense-lab", "mode": "vulnerable"},
            json.loads(response.body),
        )

    def test_vulnerable_mode_exports_restricted_dummy_file(self):
        response = self.app().handle(
            "GET", "/export?key=restricted%2Ffinance.csv", "10.0.0.8", {}
        )
        self.assertEqual(200, response.status)
        self.assertEqual(b"account,balance\nDemo,999\n", response.body)

    def test_hardened_mode_denies_restricted_key_before_store(self):
        response = self.app("hardened").handle(
            "GET", "/export?key=restricted%2Ffinance.csv", "10.0.0.8", {}
        )
        self.assertEqual(403, response.status)
        self.assertEqual([], self.store.requests)

    def test_hardened_mode_still_exports_public_report(self):
        response = self.app("hardened").handle(
            "GET", "/export?key=public%2Freport.csv", "10.0.0.8", {}
        )
        self.assertEqual(200, response.status)
        self.assertEqual(["public/report.csv"], self.store.requests)

    def test_only_fixed_export_keys_are_accepted(self):
        response = self.app().handle(
            "GET", "/export?key=restricted%2F..%2Fsecret", "10.0.0.8", {}
        )
        self.assertEqual(403, response.status)
        self.assertEqual([], self.store.requests)

    def test_log_uses_socket_peer_and_exact_schema(self):
        self.app().handle(
            "GET",
            "/export?key=public%2Freport.csv&run_id=run-7",
            "192.0.2.9",
            {"X-Forwarded-For": "203.0.113.99"},
        )
        event = json.loads(self.log.read_text().strip())
        self.assertEqual("192.0.2.9", event["srcip"])
        self.assertEqual(
            {"timestamp", "lab", "event", "srcip", "outcome", "object_key", "path",
             "request_id", "s3_request_id", "run_id", "mode", "status"},
            set(event),
        )
        self.assertEqual("/export", event["path"])
        self.assertRegex(event["timestamp"], r"^\d{4}-\d\d-\d\dT.*Z$")
        self.assertNotIn("month,total", self.log.read_text())

    def test_unknown_route_emits_probe_event(self):
        response = self.app().handle("GET", "/admin", "10.0.0.8", {})
        self.assertEqual(404, response.status)
        event = json.loads(self.log.read_text())
        self.assertEqual("probe", event["event"])
        self.assertEqual("denied", event["outcome"])
        self.assertEqual("/admin", event["path"])

    def test_s3_store_closes_body_after_bounded_read(self):
        class Body:
            closed = False
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def read(self, size):
                self.size = size
                return b"small"
        body = Body()
        client = types.SimpleNamespace(get_object=lambda **kwargs: {
            "Body": body, "ResponseMetadata": {"RequestId": "s3-1"}
        })
        boto3 = types.SimpleNamespace(client=lambda *args, **kwargs: client)
        with mock.patch.dict(sys.modules, {"boto3": boto3}):
            content, request_id = S3Store("bucket", "region").get("public/report.csv")
        self.assertEqual((b"small", "s3-1"), (content, request_id))
        self.assertTrue(body.closed)
        self.assertEqual(1_048_577, body.size)

    def test_http_adapter_logs_common_non_get_methods_and_suppresses_head_body(self):
        class FakeSocket:
            def __init__(self, request):
                self.input = __import__("io").BytesIO(request)
                self.output = __import__("io").BytesIO()
            def makefile(self, mode, buffering=None):
                return self.input if "r" in mode else self.output
            def sendall(self, data): self.output.write(data)
            def close(self): pass

        handler = make_handler(self.app())
        responses = {}
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            wire = FakeSocket(f"{method} /admin HTTP/1.1\r\nHost: lab\r\nContent-Length: 0\r\n\r\n".encode())
            handler(wire, ("198.51.100.3", 1234), object())
            responses[method] = wire.output.getvalue()
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(6, len(events))
        self.assertTrue(all(event["event"] == "probe" for event in events))
        self.assertTrue(all(response.startswith(b"HTTP/1.0 404") for response in responses.values()))
        self.assertTrue(responses["POST"].endswith(b'{"error":"not found"}'))
        self.assertTrue(responses["HEAD"].endswith(b"\r\n\r\n"))


if __name__ == "__main__":
    unittest.main()
