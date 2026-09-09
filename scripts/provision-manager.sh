#!/bin/bash
set -euo pipefail
umask 077
base=/opt/aws-defense-lab
install -d -m 0700 /root/wazuh-install
cd /root/wazuh-install
curl -fsSL --retry 5 https://packages.wazuh.com/4.14/wazuh-install.sh -o wazuh-install.sh
# A mutable upstream URL must match the reviewed installer, otherwise fail closed.
echo '8ebe9514688ace8af9445805e8887cd491dd9f95fa9d421a70f0ea012ab06f3a  wazuh-install.sh' | sha256sum -c -
bash wazuh-install.sh -a > /root/wazuh-install/install.log 2>&1
chmod 0600 /root/wazuh-install/*
test "$(dpkg-query -W -f='${Version}' wazuh-manager)" = '4.14.7-1'
apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard
# Wazuh 4.14.7 ships a shell launcher and its own Python/dependencies.
# Keep that launcher intact; changing its shebang to Python breaks it.
/var/ossec/wodles/aws/aws-s3 --help >/dev/null
python3 "$base/scripts/configure_wazuh.py" manager
# Seed only our owned manager's private IP, labelled synthetic by importer.
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)
manager_ip=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/local-ipv4)
python3 "$base/threat-intel/import_indicators.py" --input "$base/threat-intel/indicators.json" --output /var/ossec/etc/lists/defense-lab-ips --add-lab-ip "$manager_ip"
chown root:wazuh /var/ossec/etc/rules/defense_lab.xml /var/ossec/etc/lists/defense-lab-ips
chmod 0640 /var/ossec/etc/rules/defense_lab.xml /var/ossec/etc/lists/defense-lab-ips
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-modulesd -t
systemctl restart wazuh-manager
for attempt in $(seq 1 12); do
  if python3 "$base/scripts/test_wazuh_rules.py" --ioc-ip "$manager_ip" --data-bucket "$DATA_BUCKET"; then break; fi
  if [ "$attempt" = 12 ]; then exit 1; fi
  sleep 5
done
# Check IAM/list access without requiring first CloudTrail delivery or racing its poller.
/var/ossec/framework/python/bin/python3 - <<'CHECK_AUDIT'
import boto3, os
boto3.client('s3', region_name=os.environ['AWS_REGION']).list_objects_v2(
    Bucket=os.environ['LOG_BUCKET'], Prefix='AWSLogs/'+os.environ['AWS_ACCOUNT_ID']+'/', MaxKeys=1)
print('Audit bucket list access verified; first CloudTrail delivery may still be pending.')
CHECK_AUDIT
for attempt in $(seq 1 60); do
  if python3 "$base/scripts/check_dashboard.py"; then break; fi
  sleep 5
done
python3 "$base/scripts/check_dashboard.py"

cat > /etc/systemd/system/defense-lab-intel.service <<'SERVICE'
[Unit]
Description=Refresh synthetic lab indicators and expire stale entries
After=wazuh-manager.service network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/aws-defense-lab/scripts/refresh_intel.sh
SERVICE
cat > /etc/systemd/system/defense-lab-intel.timer <<'TIMER'
[Unit]
Description=Hourly lab indicator refresh
[Timer]
OnBootSec=1h
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now defense-lab-intel.timer
