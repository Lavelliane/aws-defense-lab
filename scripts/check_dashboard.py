#!/usr/bin/env python3
"""Check the local dashboard using installer credentials without logging secrets."""
import base64
import json
import re
import ssl
import tarfile
import urllib.error
import urllib.request


def admin_password(contents):
    match = re.search(
        r"indexer_username:\s*'admin'\s+indexer_password:\s*'([^']+)'", contents
    )
    if not match:
        raise ValueError('Admin credentials missing from installer archive')
    return match[1]


def healthy(payload):
    return payload.get('status', {}).get('overall', {}).get('state') == 'green'


def main():
    try:
        with tarfile.open('/root/wazuh-install/wazuh-install-files.tar') as archive:
            contents = archive.extractfile('wazuh-install-files/wazuh-passwords.txt').read().decode()
        token = base64.b64encode(('admin:' + admin_password(contents)).encode()).decode()
        request = urllib.request.Request(
            'https://127.0.0.1/api/status', headers={'Authorization': 'Basic ' + token}
        )
        # The installer uses a self-signed certificate. Keep credentials on loopback
        # and refuse redirects rather than forwarding authorization elsewhere.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        )
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or not healthy(json.load(response)):
                raise ValueError('Dashboard is not healthy')
    except (OSError, ValueError, KeyError, AttributeError, tarfile.TarError):
        # Never print exception details, archive contents, or the response body.
        raise SystemExit('Dashboard readiness check failed') from None
    print('PASS: authenticated dashboard status is green')


if __name__ == '__main__':
    main()
