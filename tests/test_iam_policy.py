import json
from pathlib import Path
import unittest

class DeploymentPolicyTests(unittest.TestCase):
    def statements(self):
        source=Path('bootstrap/ec2-policy.json.tftpl').read_text()
        for key,value in {'region':'ap-southeast-1','account':'123456789012','lab_name':'defense-lab'}.items():
            source=source.replace('${'+key+'}',value)
        return json.loads(source)
    def test_destructive_actions_require_owned_tags_and_region(self):
        guarded={'ec2:TerminateInstances','ec2:DeleteVpc','ec2:DeleteSubnet','ec2:DeleteSecurityGroup','ec2:ModifyInstanceAttribute'}
        seen=set()
        for statement in self.statements():
            actions=statement['Action']
            if isinstance(actions,str): actions=[actions]
            if guarded.intersection(actions):
                conditions=statement['Condition']['StringEquals']
                self.assertEqual(conditions['aws:ResourceTag/Lab'],'defense-lab')
                self.assertEqual(conditions['aws:ResourceTag/Project'],'aws-defense-lab')
                self.assertEqual(conditions['aws:RequestedRegion'],'ap-southeast-1')
                seen.update(guarded.intersection(actions))
        self.assertEqual(seen,guarded)
    def test_existing_resources_cannot_be_retagged_into_lab(self):
        for statement in self.statements():
            actions=statement['Action']
            if isinstance(actions,str): actions=[actions]
            if 'ec2:CreateTags' in actions:
                condition=statement['Condition']['StringEquals']
                self.assertTrue('ec2:CreateAction' in condition or condition.get('aws:ResourceTag/Lab')=='defense-lab')
