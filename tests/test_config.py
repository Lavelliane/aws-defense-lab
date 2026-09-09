import unittest
import xml.etree.ElementTree as ET
from scripts.configure_wazuh import configure

class ConfigTests(unittest.TestCase):
    def test_manager_idempotent_and_preserves_vendor_config(self):
        original = '<ossec_config><ruleset><rule_dir>ruleset/rules</rule_dir></ruleset><global><jsonout_output>yes</jsonout_output></global></ossec_config>'
        env = {'LOG_BUCKET':'audit','AWS_ACCOUNT_ID':'123456789012'}
        first=configure(original,'manager',env)
        second=configure(first,'manager',env)
        root=ET.fromstring('<root>'+second+'</root>')
        self.assertEqual(len(root.findall('.//wodle')),1)
        self.assertEqual(len(root.findall('.//list')),1)
        self.assertEqual(root.findtext('.//jsonout_output'),'yes')
        self.assertIsNone(root.find('.//aws_profile'))
    def test_agent_updates_all_logs_without_duplicate(self):
        original='<ossec_config><client><server><address>old</address></server></client></ossec_config><ossec_config><localfile><location>/var/log/auth.log</location></localfile></ossec_config>'
        env={'MANAGER_IP':'10.77.1.10'}
        result=configure(configure(original,'app',env),'app',env)
        root=ET.fromstring('<root>'+result+'</root>')
        self.assertEqual(root.findtext('.//server/address'),'10.77.1.10')
        self.assertEqual([x.text for x in root.findall('.//localfile/location')].count('/var/log/defense-lab/app.jsonl'),1)
        self.assertIn('/var/log/auth.log',[x.text for x in root.findall('.//localfile/location')])
