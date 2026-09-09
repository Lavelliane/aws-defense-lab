import unittest
from scripts.collect_evidence import select_evidence

class EvidenceTests(unittest.TestCase):
    def test_join_only_request_id_from_this_run(self):
        events=[
            {'timestamp':'2026-09-09T12:00:00Z','rule':{'id':'110012'},'data':{'lab':'aws-defense-lab','run_id':'run1','s3_request_id':'request1','object_key':'restricted/finance.csv'}},
            {'timestamp':'2026-09-09T12:01:00Z','rule':{'id':'110030'},'data':{'aws':{'requestID':'request1','requestParameters':{'bucketName':'dummy','key':'restricted/finance.csv'}}}},
            {'timestamp':'2026-09-09T12:01:00Z','rule':{'id':'110030'},'data':{'aws':{'requestID':'another','requestParameters':{'bucketName':'dummy','key':'restricted/finance.csv'}}}},
        ]
        result=select_evidence(events,'run1','dummy')
        self.assertEqual(len(result['cloudtrail']),1)
        self.assertEqual(result['cloudtrail'][0]['request_id'],'request1')
    def test_no_app_record_cannot_claim_cloud_correlation(self):
        result=select_evidence([], 'missing', 'dummy')
        self.assertEqual(result['application'],[])
        self.assertEqual(result['cloudtrail'],[])
