#!/usr/bin/env python3
"""Fail early on missing repo variables; never evaluate configuration as shell code."""
import ipaddress
import os
import re

PATTERNS={
 'AWS_REGION':r'[a-z]{2}-[a-z]+-[0-9]+',
 'TF_VAR_lab_name':r'[a-z][a-z0-9-]{2,19}',
 'STATE_BUCKET':r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]',
 'DEPLOY_ROLE':r'arn:aws:iam::[0-9]{12}:role/aws-defense-bootstrap/[a-z0-9-]+',
 'TF_VAR_permissions_boundary_arn':r'arn:aws:iam::[0-9]{12}:policy/aws-defense-lab/[a-z0-9-]+-boundary',
}
if __name__=='__main__':
    for name,pattern in PATTERNS.items():
        if not re.fullmatch(pattern,os.environ.get(name,'')):
            raise SystemExit(f'Missing or invalid repository variable: {name}')
    cidr=ipaddress.ip_network(os.environ.get('TF_VAR_allowed_cidr',''),strict=True)
    if cidr.version!=4 or cidr.prefixlen!=32:
        raise SystemExit('ALLOWED_CIDR must be your operator IPv4 /32')
    print('Repository configuration validated')
