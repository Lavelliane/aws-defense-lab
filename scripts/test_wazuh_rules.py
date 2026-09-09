#!/usr/bin/env python3
"""Execute real Wazuh logtest against synthetic fixtures on the manager."""
import argparse
import json
from pathlib import Path
import subprocess

BASE = Path(__file__).resolve().parents[1]

def cases(ioc_ip, bucket):
    base = dict(lab='aws-defense-lab', event='export', srcip='198.51.100.88', outcome='allowed', object_key='restricted/finance.csv', run_id='synthetic-rule-test')
    aws = {'integration': 'aws', 'aws': {'source': 'cloudtrail', 'eventName': 'GetObject', 'eventSource': 's3.amazonaws.com', 'requestParameters': {'bucketName': bucket, 'key': 'restricted/finance.csv'}}}
    return [
        ('restricted-unknown-ip', '110010:10:json', base),
        ('restricted-ioc-ip', '110012:12:json', dict(base, srcip=ioc_ip)),
        ('denied-unknown-ip', '110011:5:json', dict(base, outcome='denied')),
        ('denied-ioc-ip', '110013:7:json', dict(base, srcip=ioc_ip, outcome='denied')),
        ('probe-unknown-ip', '110020:5:json', dict(base, event='probe', object_key='', outcome='denied')),
        ('probe-ioc-ip', '110021:7:json', dict(base, event='probe', object_key='', outcome='denied', srcip=ioc_ip)),
        ('cloudtrail-read', '110030:8:json', aws),
        ('cloudtrail-denied', '110031:5:json', dict(aws, aws=dict(aws['aws'], errorCode='AccessDenied'))),
    ]

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--ioc-ip', required=True)
    p.add_argument('--data-bucket', required=True)
    p.add_argument('--binary', default='/var/ossec/bin/wazuh-logtest')
    args = p.parse_args()
    for name, expected, event in cases(args.ioc_ip, args.data_bucket):
        result = subprocess.run([args.binary, '-U', expected], input=json.dumps(event)+'\n', capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise SystemExit(f'{name} failed:\n{result.stdout}\n{result.stderr}')
        print(f'PASS {name}: {expected}')
