#!/usr/bin/env python3
"""Operate only instance IDs from this lab's Terraform outputs through SSM."""
import argparse
import json
import re
import shlex
import subprocess
import time
import uuid

BASE='/opt/aws-defense-lab'


def load_outputs():
    raw=subprocess.check_output(['terraform','-chdir=terraform','output','-json'],text=True)
    return {k:v['value'] for k,v in json.loads(raw).items()}


def validate_instances(ec2, outputs):
    ids=[outputs['manager_instance_id'],outputs['app_instance_id']]
    response=ec2.describe_instances(InstanceIds=ids)
    seen=set()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            tags={t['Key']:t['Value'] for t in instance.get('Tags',[])}
            if tags.get('Project')!='aws-defense-lab' or tags.get('Lab')!=outputs['lab_name']:
                raise RuntimeError('Refusing instance without matching lab tags')
            seen.add(instance['InstanceId'])
    if seen!=set(ids):
        raise RuntimeError('Missing expected lab instance')


def command(ssm, instance, script, timeout=1800):
    response=ssm.send_command(InstanceIds=[instance],DocumentName='AWS-RunShellScript',
        Parameters={'commands':['set -eu\n'+script], 'executionTimeout':[str(timeout)]},TimeoutSeconds=120)
    command_id=response['Command']['CommandId']
    deadline=time.monotonic()+timeout+150
    while time.monotonic()<deadline:
        try:
            result=ssm.get_command_invocation(CommandId=command_id,InstanceId=instance)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(3)
            continue
        status=result['Status']
        if status=='Success':
            return result.get('StandardOutputContent','')
        if status in {'Failed','Cancelled','TimedOut','Cancelling'}:
            # Do not dump arbitrary instance output, which might contain installer secrets.
            raise RuntimeError(f'SSM command {command_id} {status}; inspect its private result in AWS Systems Manager.')
        time.sleep(5)
    raise TimeoutError(f'SSM command {command_id} exceeded wait deadline')


def wait_online(ssm, ids, timeout=900):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        online={x['InstanceId'] for x in ssm.describe_instance_information(Filters=[{'Key':'InstanceIds','Values':ids}])['InstanceInformationList'] if x['PingStatus']=='Online'}
        if online==set(ids): return
        time.sleep(10)
    raise TimeoutError('Lab hosts did not register with Systems Manager')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['ready','scenario'])
    parser.add_argument('--scenario',choices=['probe','exploit','verify'])
    parser.add_argument('--confirm-lab',action='store_true')
    args=parser.parse_args()
    if args.action=='scenario' and (not args.scenario or not args.confirm_lab):
        parser.error('scenario requires --scenario and --confirm-lab')
    import boto3
    outputs=load_outputs()
    ssm=boto3.client('ssm'); ec2=boto3.client('ec2')
    validate_instances(ec2,outputs)
    manager=outputs['manager_instance_id']; app=outputs['app_instance_id']
    wait_online(ssm,[manager,app])
    if args.action=='ready':
        # These checks never run attacks. READY follows each bootstrap's local gates.
        for instance in (manager,app):
            command(ssm,instance, f'for n in $(seq 1 240); do test ! -f {BASE}/READY || break; sleep 5; done\ntest -f {BASE}/READY')
        command(ssm,app,"systemctl is-active --quiet defense-lab-app wazuh-agent\ncurl -fsS http://127.0.0.1:8080/health\n"
            "for n in $(seq 1 60); do grep -q \"^status='connected'$\" /var/ossec/var/run/wazuh-agentd.state && exit 0; sleep 5; done\nexit 1")
        command(ssm,manager,'systemctl is-active --quiet wazuh-manager wazuh-indexer wazuh-dashboard filebeat\n'+
            f'for n in $(seq 1 60); do /var/ossec/bin/agent_control -lc | grep -F {shlex.quote(outputs["lab_name"]+"-app-")} && exit 0; sleep 5; done\nexit 1')
        print('PASS: application healthy, Wazuh services active, application agent connected.')
        print('CloudTrail detection readiness is verified separately by the scenario evidence gate.')
        return
    expected_mode='hardened' if args.scenario=='verify' else 'vulnerable'
    if args.scenario!='probe' and outputs['app_mode']!=expected_mode:
        raise RuntimeError(f'Deploy {expected_mode} mode before this scenario')
    run_id='demo-'+uuid.uuid4().hex[:16]
    script=f'python3 {BASE}/scenarios/run.py --target {shlex.quote(outputs["app_private_url"])} --scenario {args.scenario} --run-id {run_id} --confirm-lab'
    print(command(ssm,manager,script,timeout=120).strip())
    extra=''
    if args.scenario=='verify':
        script=f'set -a\n. /etc/defense-lab.env\nset +a\n{BASE}/.venv/bin/python {BASE}/scripts/check_iam.py'
        iam=json.loads(command(ssm,app,script,timeout=120))
        if not iam.get('iam_denied') or not re.fullmatch('[A-Za-z0-9]+',iam.get('request_id','')):
            raise RuntimeError('IAM verification did not return a valid denial request ID')
        extra=' --request-id '+shlex.quote(iam['request_id'])
    script=f'python3 {BASE}/scripts/collect_evidence.py --run-id {run_id} --data-bucket {shlex.quote(outputs["data_bucket"])} --expect {args.scenario}'+extra
    print(command(ssm,manager,script,timeout=1100).strip())

if __name__=='__main__':
    main()
