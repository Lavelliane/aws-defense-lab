# Costs and troubleshooting

## Cost footprint

This lab is **not promised to fit a free tier**. Defaults are one t3.xlarge manager (4 vCPU, 16 GiB), one t3.micro app, 62 GiB of encrypted gp3 storage in total, two public IPv4 addresses, three versioned S3 buckets, and a multi-region CloudTrail with selected data events. Bootstrap adds a small versioned state bucket. S3 requests/storage, CloudTrail data events, instance CPU-credit surplus where applicable, and data transfer may add charges. There is no NAT gateway, load balancer, GuardDuty, CloudTrail Lake or paid third-party intelligence feed in this version.

Check the AWS Pricing Calculator for your region and set an account budget alert before deploying. Budget alerts notify; they are not a spending cap. Stop/destroy promptly after recording. Stopping EC2 does not remove EBS or S3 charges. Destroy Lab + PURGE deletes the lab resources; bootstrap storage remains.

Official pricing: https://calculator.aws/ ; https://aws.amazon.com/ec2/pricing/ ; https://aws.amazon.com/vpc/pricing/ ; https://aws.amazon.com/cloudtrail/pricing/ ; https://aws.amazon.com/s3/pricing/

## Failure guide

| Symptom | Check |
|---|---|
| OIDC access denied | Exact OWNER/REPO case, main branch, role ARN, provider audience sts.amazonaws.com; no environment-based subject is used in v1 |
| Bootstrap OIDC already exists | Supply existing_oidc_provider_arn and retry after reviewing the plan |
| Terraform cannot create runtime role | Bootstrap boundary ARN and required deployment IAM policy; do not remove boundary to bypass the error |
| EC2 fails startup | Systems Manager session: sudo tail /var/log/defense-lab-bootstrap.log; cloud-init status --long |
| Manager installer SHA mismatch | Upstream 4.14 installer changed. Review official installer version/checksum and package pin together, then rebuild; never bypass checksum |
| Wazuh install fails | Root-only /root/wazuh-install/install.log; memory/disk, outbound package access, package version availability |
| Agent disconnected | Private manager IP, TCP 1514 and 1515 security-group reference, agent service/log /var/ossec/logs/ossec.log |
| Dashboard unreachable | Current operator /32, public IP, HTTPS 443, instance readiness and self-signed certificate |
| CloudTrail missing | Trail enabled, audit bucket policy, selected dummy GetObject data events, S3 delivery delay |
| CloudTrail in S3 but absent from Wazuh | Manager role read/list permissions, /var/ossec/logs/ossec.log AWS-module errors, vendor embedded Python/launcher |
| Scenario HTTP 502 | App service log; DATA_BUCKET, role permissions, S3 connectivity. 502 is not a successful hardened denial |
| Enriched alert absent | Source address equals seeded manager IP, valid indicator expiry, CDB refresh, custom rule validation |
| Evidence gate times out | Inspect current-day alerts, rule IDs, app s3_request_id and CloudTrail requestID; rerun before midnight UTC to avoid file rotation across a long wait |
| Destroy bucket not empty | Versioned objects exist; use explicit PURGE workflow after evidence export |
| No SSM session | Your human IAM session permissions and SSM plugin; hosts need outbound internet and active amazon-ssm-agent |

The application is intentionally tiny and supports fixed GET routes. File contents are bounded at 1 MiB. It has no SQL, command execution, credential dump, arbitrary outbound-fetch endpoint or internet scanner. An unknown-route probe is a signal to investigate, not a general-purpose attack classifier.

The exact Ubuntu AMI resolves at each Terraform plan from Canonical's current Jammy image. Wazuh is pinned to 4.14.7-1 and installer bytes are pinned. Terraform provider lockfiles preserve reviewed provider selections. GitHub action major tags are tracked by Dependabot; organizations needing immutable action references should pin reviewed commit SHAs before wider reuse.
