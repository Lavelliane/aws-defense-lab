#!/usr/bin/env python3
import argparse
import json
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class ScenarioError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = build_opener(_NoRedirect)


def urlopen(request, timeout):
    return _opener.open(request, timeout=timeout)


def validate_target(target):
    parsed = urlsplit(target)
    if (parsed.scheme != "http" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ScenarioError("target must be a plain http origin without credentials, path, query, or fragment")
    if parsed.port is None:
        raise ScenarioError("target must include the lab application port")
    return target.rstrip("/")


def _request(base, path):
    expected = base + path
    request = Request(expected, headers={"User-Agent": "aws-defense-lab-scenario/1"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    if 300 <= response.status < 400 or response.geturl() != expected:
        response.close()
        raise ScenarioError("redirect refused")
    with response:
        return response.status, response.read(65537)


def run_scenario(target, scenario, run_id):
    base = validate_target(target)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", run_id):
        raise ScenarioError("run-id must contain 1-64 safe characters")
    status, body = _request(base, "/health")
    try:
        health = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ScenarioError("lab identity check returned invalid JSON") from None
    if status != 200 or not isinstance(health, dict) or health.get("lab_id") != "aws-defense-lab":
        raise ScenarioError("lab identity check failed")
    if scenario == "probe":
        for path in ("/admin", "/login", "/.env", "/debug", "/backup"):
            _request(base, f"{path}?run_id={quote(run_id)}")
        return {"scenario": scenario, "requests": 5, "mode": health.get("mode"), "run_id": run_id}
    required_mode = "vulnerable" if scenario == "exploit" else "hardened"
    if health.get("mode") != required_mode:
        raise ScenarioError(f"{scenario} requires application mode {required_mode}")
    path = f"/export?key=restricted%2Ffinance.csv&run_id={quote(run_id)}"
    export_status, _ = _request(base, path)
    expected = 200 if scenario == "exploit" else 403
    if export_status != expected:
        raise ScenarioError(f"{scenario} expected HTTP {expected}, got {export_status}")
    return {"scenario": scenario, "requests": 1, "status": export_status,
            "mode": health.get("mode"), "run_id": run_id}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a bounded AWS Defense Lab scenario")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scenario", required=True, choices=("probe", "exploit", "verify"))
    parser.add_argument("--confirm-lab", action="store_true")
    parser.add_argument("--run-id", default="manual")
    args = parser.parse_args(argv)
    if not args.confirm_lab:
        parser.error("--confirm-lab is required")
    try:
        print(json.dumps(run_scenario(args.target, args.scenario, args.run_id), sort_keys=True))
    except ScenarioError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
