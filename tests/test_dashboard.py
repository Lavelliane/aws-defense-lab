import unittest

from scripts.check_dashboard import admin_password, healthy


class DashboardTests(unittest.TestCase):
    def test_selects_admin_among_service_credentials(self):
        fixture = """indexer_username: 'kibanaserver'
indexer_password: 'service-example'
# Dashboard administrator
indexer_username: 'admin'
indexer_password: 'test-only-example'
api_username: 'wazuh'
api_password: 'api-example'
"""
        self.assertEqual(admin_password(fixture), 'test-only-example')

    def test_missing_admin_does_not_expose_contents(self):
        with self.assertRaisesRegex(ValueError, '^Admin credentials missing from installer archive$'):
            admin_password("indexer_password: 'test-only-secret'")

    def test_only_green_status_is_ready(self):
        self.assertTrue(healthy({'status': {'overall': {'state': 'green'}}}))
        for state in ('red', 'yellow', 'unknown'):
            self.assertFalse(healthy({'status': {'overall': {'state': state}}}))
        self.assertFalse(healthy({}))
