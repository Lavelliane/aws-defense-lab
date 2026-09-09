#!/bin/bash
set -euo pipefail
umask 022
base=/opt/aws-defense-lab
python3 -m venv "$base/.venv"
"$base/.venv/bin/pip" install --disable-pip-version-check -r "$base/app/requirements.txt"
getent passwd labapp >/dev/null || useradd --system --home-dir "$base" --shell /usr/sbin/nologin labapp
install -d -m 0750 -o labapp -g labapp /var/log/defense-lab
install -m 0640 -o labapp -g labapp /dev/null /var/log/defense-lab/app.jsonl
cat > /etc/systemd/system/defense-lab-app.service <<'SERVICE'
[Unit]
Description=AWS Defense Lab synthetic export application
After=network-online.target
Wants=network-online.target
[Service]
User=labapp
Group=labapp
WorkingDirectory=/opt/aws-defense-lab
EnvironmentFile=/etc/defense-lab.env
Environment=APP_LOG_PATH=/var/log/defense-lab/app.jsonl
Environment=PORT=8080
ExecStart=/opt/aws-defense-lab/.venv/bin/python /opt/aws-defense-lab/app/server.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/defense-lab
ProtectHome=true
PrivateTmp=true
UMask=0027
[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable --now defense-lab-app
curl -fsSL --retry 5 https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh-key
install -d /usr/share/keyrings
gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh-key
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
apt-get -o DPkg::Lock::Timeout=300 update
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="${LAB_NAME}-app-$(hostname)" apt-get -o DPkg::Lock::Timeout=300 install -y wazuh-agent=4.14.7-1
apt-mark hold wazuh-agent
python3 "$base/scripts/configure_wazuh.py" app
/var/ossec/bin/wazuh-logcollector -t
systemctl daemon-reload
systemctl enable --now wazuh-agent
curl --fail --retry 15 --retry-connrefused --retry-delay 2 http://127.0.0.1:8080/health
