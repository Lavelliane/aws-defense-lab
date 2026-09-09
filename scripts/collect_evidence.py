#!/usr/bin/env python3
"""Correlate application and CloudTrail alerts by S3 request ID, never by timing alone."""
import argparse
import json
from pathlib import Path
import re
import time


def scrub(value):
    return re.sub(r'(?<!\d)\d{12}(?!\d)', '<ACCOUNT_ID>', str(value))


def select_evidence(events, run_id, bucket, extra_request_id=''):
    application=[]
    request_ids={extra_request_id} if extra_request_id else set()
    cloud=[]
    for alert in events:
        data=alert.get('data', {})
        if data.get('lab') == 'aws-defense-lab' and data.get('run_id') == run_id:
            request_id=data.get('s3_request_id', '')
            if request_id:
                request_ids.add(request_id)
            application.append({'timestamp':alert.get('timestamp'), 'rule_id':alert.get('rule',{}).get('id'),
                'outcome':data.get('outcome'), 'object_key':data.get('object_key'),
                'source_ip':data.get('srcip'), 'request_id':request_id, 'run_id':run_id})
    for alert in events:
        aws=alert.get('data',{}).get('aws',{})
        if aws.get('requestID') not in request_ids:
            continue
        if aws.get('requestParameters',{}).get('bucketName') != bucket:
            continue
        cloud.append({'timestamp':aws.get('eventTime',alert.get('timestamp')), 'rule_id':alert.get('rule',{}).get('id'),
            'event':aws.get('eventName'), 'request_id':aws.get('requestID'),
            'object_key':aws.get('requestParameters',{}).get('key'), 'error':aws.get('errorCode'),
            'identity':scrub(aws.get('userIdentity',{}).get('arn','')), 'source_ip':aws.get('sourceIPAddress')})
    return {'run_id':run_id, 'application':application, 'cloudtrail':cloud}


def load_events(path):
    with Path(path).open() as stream:
        for line in stream:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # A writer may still be finishing the last line.


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--run-id', required=True)
    p.add_argument('--data-bucket',required=True)
    p.add_argument('--request-id',default='')
    p.add_argument('--alerts',default='/var/ossec/logs/alerts/alerts.json')
    p.add_argument('--wait-seconds',type=int,default=900)
    p.add_argument('--expect',choices=['probe','exploit','verify'],required=True)
    args=p.parse_args()
    deadline=time.monotonic()+args.wait_seconds
    while True:
        events=list(load_events(args.alerts)) if Path(args.alerts).exists() else []
        evidence=select_evidence(events,args.run_id,args.data_bucket,args.request_id)
        ids={str(x['rule_id']) for x in evidence['application']}
        ready=(args.expect=='probe' and '110021' in ids) or (
            args.expect=='exploit' and '110012' in ids and any(x['event']=='GetObject' and not x['error'] for x in evidence['cloudtrail'])) or (
            args.expect=='verify' and '110013' in ids and any(x['error']=='AccessDenied' for x in evidence['cloudtrail']))
        if ready:
            print(json.dumps(dict(evidence, verified=True),indent=2))
            return 0
        if time.monotonic()>=deadline:
            print(json.dumps(dict(evidence,verified=False,reason='Expected correlated alerts did not arrive before timeout'),indent=2))
            return 1
        time.sleep(10)

if __name__=='__main__':
    raise SystemExit(main())
