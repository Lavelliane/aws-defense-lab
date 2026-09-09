# AWS Defense Lab design

Approved scope: Terraform repository providing an EC2 vulnerable export application, separate all-in-one Wazuh server, CloudTrail with selected S3 read data events, synthetic IP intelligence, bounded scenarios, hardening, and deploy/scenario/destroy GitHub workflows. No AWS deployment or attack execution is authorized by repository creation.

One-time bootstrap: GitHub OIDC trusted only for configured repository/main branch; deployment role; S3 remote state with native lock file. Bootstrap local state retained securely outside Git. Lab IAM identities use instance roles. Do not create static access keys or IAM users.

Two Ubuntu 22.04 x86_64 EC2 hosts in public subnet with outbound internet, encrypted gp3 volumes, IMDSv2. Manager t3.xlarge/50 GiB; application t3.micro/12 GiB. No SSH; use SSM. Operator IPv4 /32 required. Dashboard 443 from operator; application 8080 from operator and manager; agent TCP 1514/1515 from app security group. Agent enrollment uses private path. No public buckets.

App is a purpose-built simulated single-persona demo, not AWSGoat. Fixed demo identity is allowed public/report.csv. Vulnerable mode also permits restricted/finance.csv from dummy-data bucket via role. Hardened mode denies restricted keys before S3; IAM independently permits only public/*, explicitly denies restricted/*. Unknown routes produce probe events. No credentials or export contents in logs. /health contains lab_id=aws-defense-lab. APP_MODE changes replace only app instance. Direct IAM verification runs as app instance role.

Artifact bundle contains app/, scenarios/, threat-intel/, wazuh/, scripts/; uploaded to separate private bucket. Cloud-init invokes scripts/provision-{manager,app}.sh with environment written by Terraform. Bundle version forces EC2 replacement. Server address is private for agent.

Application JSON events include UTC timestamp and request path, plus: lab=aws-defense-lab, event=export|probe, srcip=socket peer, outcome=allowed|denied|error, object_key, request_id, s3_request_id, run_id, mode, status. Agent reads /var/log/defense-lab/app.jsonl as JSON. Wazuh custom rules 110000..110099. AWS events come via standard aws-s3 integration, fields aws.eventName/aws.requestParameters.key. Separate CDB source-IP alert must preserve behavior alerts for unknown IPs.

Runtime base /opt/aws-defense-lab; Python virtualenv there at .venv. Wazuh 4.14.7-1 packages; installer SHA256 verified from official 4.14 URL. CloudTrail uses manager role, 1m poll, management read/write + dummy-data GetObject. No data events for audit/artifact buckets to avoid feedback. Match restricted successful/denied object reads using separate rules. Agent and Wazuh config validation is a runtime gate, not a local claim.

TI offline JSON list with ip,source,description,expires_at; synthetic default TEST-NET fixture clearly labeled. During manager provisioning add its private IP as synthetic demo IOC; validate expiry, no duplicate or invalid IP; atomic CDB text update; manager restart only on change. No public feed auto-fetch.

Scenarios run over SSM on manager, HTTP to private app. Fixed endpoints and at most 5 probe requests, 1 export. Validate /health identity, refuse redirects, explicit --confirm-lab. Hardened verification expects 403 plus SSM direct IAM denied check. No automated attacks in deploy. Evidence captured in private SSM results with sanitized extract; source fixtures labeled synthetic.

Terraform state and plans may be sensitive; remote encrypted state, no public artifacts or logged secrets. Destroy workflow requires exact lab name and PURGE confirmation; force_destroy opt-in only for lab buckets, never bootstrap. CI performs local unit tests, Terraform fmt/validate/test with mock providers, shell syntax, workflow checks. Live integration needs AWS account and post-deploy gates. Do not claim real screenshots or recordings until captured.
