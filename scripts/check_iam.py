#!/usr/bin/env python3
"""Run on APP host to test actual instance-role permissions independently of HTTP."""
import json
import os
import boto3
from botocore.exceptions import ClientError

if __name__ == '__main__':
    s3=boto3.client('s3',region_name=os.environ['AWS_REGION'])
    bucket=os.environ['DATA_BUCKET']
    # Prove credentials/bucket are usable first; unrelated failures are not success.
    with s3.get_object(Bucket=bucket,Key='public/report.csv')['Body'] as body:
        body.read(4096)
    try:
        result=s3.get_object(Bucket=bucket,Key='restricted/finance.csv')
        result['Body'].close()
    except ClientError as error:
        if error.response['Error']['Code'] != 'AccessDenied':
            raise
        print(json.dumps({'iam_denied':True,'request_id':error.response['ResponseMetadata']['RequestId']}))
    else:
        raise SystemExit('FAIL: instance role can still read the restricted dummy object')
