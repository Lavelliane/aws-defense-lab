#!/bin/bash
set -euo pipefail
umask 027
base=/opt/aws-defense-lab
# Only an owned instance address is inserted, always labelled synthetic.
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)
manager_ip=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/local-ipv4)
result=$(python3 "$base/threat-intel/import_indicators.py" --input "$base/threat-intel/indicators.json" --output /var/ossec/etc/lists/defense-lab-ips --add-lab-ip "$manager_ip")
chown root:wazuh /var/ossec/etc/lists/defense-lab-ips
chmod 0640 /var/ossec/etc/lists/defense-lab-ips
if [ "$result" = CHANGED ]; then
  /var/ossec/bin/wazuh-analysisd -t
  systemctl restart wazuh-manager
fi
printf '%s\n' "$result"
