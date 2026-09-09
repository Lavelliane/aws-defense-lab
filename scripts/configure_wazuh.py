#!/usr/bin/env python3
"""Edit existing Wazuh config idempotently; keep vendor configuration intact."""
import argparse
import os
from pathlib import Path
import xml.etree.ElementTree as ET

BASE = Path('/opt/aws-defense-lab')

def configure(text, component, env):
    # Wazuh supports several ossec_config elements in one file.
    wrapper = ET.fromstring('<root>' + text + '</root>')
    cfg = wrapper.find('ossec_config')
    if cfg is None:
        raise ValueError('Missing ossec_config')
    if component == 'manager':
        for block in wrapper.findall('ossec_config'):
            for wodle in block.findall("wodle[@name='aws-s3']"):
                block.remove(wodle)
        wodle = ET.SubElement(cfg, 'wodle', {'name': 'aws-s3'})
        for name, value in [('disabled', 'no'), ('interval', '1m'), ('run_on_start', 'yes'), ('skip_on_error', 'no')]:
            ET.SubElement(wodle, name).text = value
        bucket = ET.SubElement(wodle, 'bucket', {'type': 'cloudtrail'})
        ET.SubElement(bucket, 'name').text = env['LOG_BUCKET']
        ET.SubElement(bucket, 'aws_account_id').text = env['AWS_ACCOUNT_ID']
        ruleset = cfg.find('ruleset')
        if ruleset is None:
            raise ValueError('Missing vendor ruleset')
        if not any(x.text == 'etc/lists/defense-lab-ips' for x in ruleset.findall('list')):
            ET.SubElement(ruleset, 'list').text = 'etc/lists/defense-lab-ips'
    else:
        client = cfg.find('client')
        if client is None:
            raise ValueError('Missing agent client config')
        for old in list(client.findall('server')):
            client.remove(old)
        server = ET.SubElement(client, 'server')
        for name, value in [('address', env['MANAGER_IP']), ('port', '1514'), ('protocol', 'tcp')]:
            ET.SubElement(server, name).text = value
        for block in wrapper.findall('ossec_config'):
            for old in block.findall('localfile'):
                if old.findtext('location') == '/var/log/defense-lab/app.jsonl':
                    block.remove(old)
        log = ET.SubElement(cfg, 'localfile')
        ET.SubElement(log, 'log_format').text = 'json'
        ET.SubElement(log, 'location').text = '/var/log/defense-lab/app.jsonl'
    ET.indent(wrapper, space='  ')
    return '\n'.join(ET.tostring(c, encoding='unicode') for c in wrapper)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('component', choices=['manager', 'app'])
    args = parser.parse_args()
    config = Path('/var/ossec/etc/ossec.conf')
    value = configure(config.read_text(), args.component, os.environ)
    if not config.with_suffix('.conf.original').exists():
        config.with_suffix('.conf.original').write_text(config.read_text())
    config.write_text(value)
    if args.component == 'manager':
        rules = (BASE / 'wazuh/rules/defense_lab.xml.in').read_text()
        # Terraform bucket names contain only lowercase, digits, hyphens.
        import re
        bucket = os.environ['DATA_BUCKET']
        if not re.fullmatch(r'[a-z0-9-]{3,63}', bucket):
            raise ValueError('Invalid data bucket')
        (Path('/var/ossec/etc/rules') / 'defense_lab.xml').write_text(rules.replace('__DATA_BUCKET__', bucket))
