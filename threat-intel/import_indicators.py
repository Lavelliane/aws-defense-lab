#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


class IndicatorError(ValueError):
    pass


def _ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise IndicatorError("only IPv4 indicators are supported by the Wazuh CDB key")
    return str(address)


def _expiry(value):
    if not isinstance(value, str):
        raise IndicatorError("expires_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise IndicatorError("invalid expires_at") from error
    if parsed.tzinfo is None:
        raise IndicatorError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _line(ip, source, description):
    if not all(isinstance(item, str) and item.strip() for item in (source, description)):
        raise IndicatorError("source and description must be non-empty strings")
    if any(char in source + description for char in "\r\n:"):
        raise IndicatorError("source and description cannot contain colons or newlines")
    return f"{ip}:{source.strip()} - {description.strip()}"


def import_indicators(input_path, output_path, add_lab_ip=None, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        records = json.loads(Path(input_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IndicatorError(f"cannot read indicator JSON: {error}") from error
    if not isinstance(records, list):
        raise IndicatorError("indicator JSON must be a list")
    lines = {}
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise IndicatorError("each indicator must be an object")
        try:
            ip = _ipv4(record["ip"])
            source, description = record["source"], record["description"]
            expires = _expiry(record["expires_at"])
        except (KeyError, ValueError) as error:
            raise IndicatorError(f"invalid indicator: {error}") from error
        if ip in seen:
            raise IndicatorError(f"duplicate indicator IP: {ip}")
        seen.add(ip)
        if expires <= now:
            continue
        lines[ip] = _line(ip, source, description)
    if add_lab_ip:
        try:
            lab_ip = _ipv4(add_lab_ip)
        except ValueError as error:
            raise IndicatorError("invalid lab IP") from error
        if lab_ip in seen:
            raise IndicatorError(f"duplicate indicator IP: {lab_ip}")
        lines[lab_ip] = f"{lab_ip}:synthetic lab manager IP"
    content = "".join(lines[ip] + "\n" for ip in sorted(lines, key=ipaddress.ip_address))
    output = Path(output_path)
    if output.exists() and output.read_text(encoding="utf-8") == content:
        return False
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build Wazuh CDB source-IP intelligence")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--add-lab-ip")
    args = parser.parse_args(argv)
    try:
        changed = import_indicators(args.input, args.output, args.add_lab_ip)
    except IndicatorError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print("CHANGED" if changed else "UNCHANGED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
