#!/usr/bin/env python3
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LAB_ID = "aws-defense-lab"
ALLOWED_KEYS = {"public/report.csv", "restricted/finance.csv"}
MAX_EXPORT_BYTES = 1_048_576


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json"


class S3Store:
    def __init__(self, bucket, region):
        self.bucket = bucket
        self.region = region
        self._client = None

    def get(self, key):
        if self._client is None:
            import boto3
            self._client = boto3.client("s3", region_name=self.region)
        response = self._client.get_object(Bucket=self.bucket, Key=key)
        request_id = response.get("ResponseMetadata", {}).get("RequestId", "")
        with response["Body"] as stream:
            content = stream.read(MAX_EXPORT_BYTES + 1)
        if len(content) > MAX_EXPORT_BYTES:
            raise ValueError("dummy export exceeds size limit")
        return content, request_id


class ExportApplication:
    def __init__(self, mode, store, log_path):
        if mode not in {"vulnerable", "hardened"}:
            raise ValueError("APP_MODE must be vulnerable or hardened")
        self.mode = mode
        self.store = store
        self.log_path = Path(log_path)

    def _log(self, *, event, srcip, outcome, object_key, path, request_id,
             s3_request_id, run_id, status):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "lab": LAB_ID, "event": event, "srcip": srcip,
            "outcome": outcome, "object_key": object_key,
            "path": path,
            "request_id": request_id, "s3_request_id": s3_request_id,
            "run_id": run_id, "mode": self.mode, "status": status,
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")

    def handle(self, method, target, peer_ip, headers):
        del headers
        parsed = urlsplit(target)
        if method == "GET" and parsed.path == "/health":
            return Response(200, json.dumps({"lab_id": LAB_ID, "mode": self.mode}).encode())
        request_id = str(uuid.uuid4())
        query = parse_qs(parsed.query)
        run_id = query.get("run_id", [""])[0][:128]
        if method != "GET" or parsed.path != "/export":
            self._log(event="probe", srcip=peer_ip, outcome="denied", object_key="", path=parsed.path,
                      request_id=request_id, s3_request_id="", run_id=run_id, status=404)
            return Response(404, b'{"error":"not found"}')
        key = query.get("key", [""])[0]
        if key not in ALLOWED_KEYS or (self.mode == "hardened" and key.startswith("restricted/")):
            self._log(event="export", srcip=peer_ip, outcome="denied", object_key=key, path=parsed.path,
                      request_id=request_id, s3_request_id="", run_id=run_id, status=403)
            return Response(403, b'{"error":"access denied"}')
        try:
            body, s3_request_id = self.store.get(key)
            self._log(event="export", srcip=peer_ip, outcome="allowed", object_key=key, path=parsed.path,
                      request_id=request_id, s3_request_id=s3_request_id, run_id=run_id, status=200)
            return Response(200, body, "text/csv")
        except Exception:
            self._log(event="export", srcip=peer_ip, outcome="error", object_key=key, path=parsed.path,
                      request_id=request_id, s3_request_id="", run_id=run_id, status=502)
            return Response(502, b'{"error":"storage unavailable"}')


def make_handler(application):
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self):
            response = application.handle(self.command, self.path, self.client_address[0], self.headers)
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)

        do_GET = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch
        do_PATCH = _dispatch
        do_DELETE = _dispatch
        do_OPTIONS = _dispatch
        do_HEAD = _dispatch

        def log_message(self, format, *args):
            return
    return Handler


def main():
    mode = os.environ.get("APP_MODE", "vulnerable")
    bucket = os.environ["DATA_BUCKET"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    log_path = os.environ.get("APP_LOG_PATH", "/var/log/defense-lab/app.jsonl")
    port = int(os.environ.get("PORT", "8080"))
    app = ExportApplication(mode, S3Store(bucket, region), log_path)
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(app)).serve_forever()


if __name__ == "__main__":
    main()
