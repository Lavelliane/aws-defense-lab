# Deploy, operate, and clean up

## One-time setup

Use a dedicated AWS lab account and an existing authorized federated/SSO session. You need Terraform 1.13.5, Python 3.10+, AWS CLI v2, and the Session Manager plugin if you want interactive sessions. GitHub must have Actions enabled.

1. Create a GitHub repository from this source, with default branch **main**. Keep the workflows on main; the AWS trust policy and workflow job guards reject other branches.
2. Copy `bootstrap/terraform.tfvars.example` to `bootstrap/terraform.tfvars`. Set exact `OWNER/REPOSITORY`, region and lab name. If GitHub OIDC already exists in the AWS account, set `existing_oidc_provider_arn` to that provider instead of creating another.
3. Authenticate locally, then run:

```bash
aws sso login --profile your-lab
export AWS_PROFILE=your-lab
terraform -chdir=bootstrap init
terraform -chdir=bootstrap plan
terraform -chdir=bootstrap apply
terraform -chdir=bootstrap output -json github_variables
```

4. In GitHub **Settings → Secrets and variables → Actions → Variables**, add the five values from `github_variables`: `AWS_ROLE_ARN`, `AWS_REGION`, `TF_STATE_BUCKET`, `LAB_NAME`, `PERMISSIONS_BOUNDARY_ARN`. Also add `ALLOWED_CIDR` with your current public IPv4 `/32`.
5. Protect main from unreviewed changes. Anyone able to execute trusted repository code has the deployment role's capabilities. Never give untrusted contributors write access to this repository.

Bootstrap Terraform state remains local and is Git-ignored. Back it up to controlled encrypted storage; it owns the OIDC/role/boundary/state bucket. The *lab* state is remotely versioned in S3 with native lock files. Neither lab teardown nor its deployment role deletes bootstrap state.

## Deploy button

**Actions → Deploy Lab → Run workflow → vulnerable.** One workflow launch after the above bootstrap performs plan/apply and startup checks; it does not execute attacker scripts. Installing Wazuh takes several minutes. Budget enough preparation time for downloads and eventual consistency.

A green deploy means the app is healthy, Wazuh services are active and the application agent is connected. It does not establish CloudTrail delivery or successful alert correlation; the separate scenario gate checks those.

Public app and dashboard URLs appear in workflow output. They are restricted by `ALLOWED_CIDR`. If your IP changes, update that repository variable and redeploy. There is no AWS IAM user, access key, SSH key or dashboard password in Terraform output.

## Dashboard password

Open **EC2 → manager instance → Connect → Session Manager** using your own authorized AWS identity. The GitHub role intentionally has Run Command permissions, not interactive session permissions. Your human access policy needs SSM session access to this lab.

Inside the manager's interactive session:

```bash
sudo tar -xOf /root/wazuh-install/wazuh-install-files.tar \
  wazuh-install-files/wazuh-passwords.txt
```

Use the `admin` indexer user/password for the dashboard. Keep this output private and never record it. The vendor install archive contains several service credentials. The installer log and archive are root-only; no credential is uploaded as a GitHub artifact. The self-signed dashboard certificate warning is expected for this private lab endpoint.

## Scenario button and evidence

**Actions → Run Lab Scenario → probe or exploit → type your lab name.** The runner checks instance tags, the app's `/health` identity and mode, refuses redirects, and sends only fixed bounded requests. It runs on the manager to make the seeded synthetic IP match repeatable. The workflow waits up to 15 minutes for the expected alerts and prints selected, account-redacted evidence.

Each workflow run gets a unique run ID. Probe requires rule 110021. Exploit requires rule 110012 and a successful correlated CloudTrail read. A timeout is a failed verification, not a successful attack demonstration. Check SSM command history privately for failure details; automatic error output is deliberately limited to avoid exposing vendor install secrets.

Run **Deploy Lab → hardened**, then **Run Lab Scenario → verify**. Verification requires application denial, actual instance-role denial, and their expected Wazuh evidence. Deploying hardened mode changes the application instance ID. Existing unrelated agents may remain disconnected in Wazuh inventory; inspect the current ID/name.

## Local Terraform alternative

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r app/requirements.txt
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
cp terraform/backend.hcl.example terraform/backend.hcl
# Edit both files with your bootstrap outputs, region and IP.
make bundle
make init
make deploy
make ready
make exploit
make harden
make verify
```

`AWS_REGION` must be exported for boto3 operations and match the Terraform region. `AWS_PROFILE` may supply your federated local credentials. `make validate` initializes an offline backend for validation; if switching that working directory back to a real backend, run `terraform -chdir=terraform init -reconfigure -backend-config=backend.hcl`.

## Teardown

Before deleting the manager, save any screenshots or selected alerts needed for the talk. Its EBS alert/index data is ephemeral. No real evidence is prepackaged in this repository.

For a complete lab cleanup: **Actions → Destroy Lab → type the exact lab name → type PURGE**. This explicitly deletes all lab bucket objects and versions, including CloudTrail logs. The workflow first applies `force_destroy=true` only to the three lab bucket resources, then destroys the lab. Targeting is used solely for this teardown flag and cannot rebuild EC2 instances.

The default `make destroy` keeps bucket deletion guarded: nonempty/versioned buckets will block cleanup. To retain logs, export them to your own controlled destination before selecting PURGE; do not remove resources from Terraform state as a substitute for cleanup.

Bootstrap resources remain deliberately: state bucket and versions, deployment role, permissions boundary, and any OIDC provider created by bootstrap. Remove them separately only after all lab resources are gone and you have decided to retire the repository. `prevent_destroy` guards the bootstrap bucket. An existing shared OIDC provider supplied by ARN is never owned by this bootstrap.
