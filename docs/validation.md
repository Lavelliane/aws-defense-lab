# Validation status

Repository implementation completed on 2026-09-09. No AWS account was deployed, no cloud attacks were executed, and no real alert screenshots or recordings were produced by this build.

| Check | Result |
|---|---|
| Python application, HTTP adapter, scenario, indicator, config, evidence-correlation and IAM guard tests | PASS: 28 tests |
| Python compile checks | PASS |
| Terraform HCL formatting/parser check, Terraform 1.13.5 | PASS |
| GitHub workflow validation, actionlint 1.7.7 | PASS |
| Bash syntax for app, manager and indicator-refresh scripts | PASS |
| Deterministic runtime bundle and source archive checks | PASS at packaging |
| Wazuh 4.14.7 native AWS integration launcher `--help`, from official extracted package | PASS; confirms packaged launcher/dependencies, not AWS authentication |
| Independent review of application and infrastructure changes | Completed; identified IAM scope, HTTP logging and indicator-file permission issues were addressed |
| Terraform provider schema validation and mocked infrastructure execution | BLOCKED locally: runtime denies provider Unix socket creation (`listen unix /tmp/plugin...: operation not permitted`). Included CI runs these without AWS credentials |
| Installed Wazuh rule-engine tests | NOT RUN locally: installed service environment/user absent. Eight runtime cases are a manager provisioning gate |
| AWS IAM evaluation, EC2/cloud-init readiness, CloudTrail delivery and detection, complete teardown | NOT RUN: requires an actual lab-account deployment |

The mock-provider tests in `terraform/tests/lab.tftest.hcl` check vulnerable/hardened IAM, IMDSv2, public-access blocks and rejected inputs. Mock `apply` means in-memory test resources, not AWS deployment. Do not describe these tests as passing until CI executes them successfully.

## First deployment acceptance

1. Validation CI is green, including both Terraform roots and all mock tests.
2. Bootstrap is applied by an authorized identity and repository variables are correct.
3. Deploy Lab succeeds: host bootstrap marker, native AWS module import/CLI, eight rule fixtures, audit-bucket list access, active services and connected app agent.
4. Probe: run-specific Wazuh rule 110021 arrives.
5. Exploit: restricted dummy export returns 200, rule 110012 arrives and a CloudTrail GetObject joins by exact S3 request ID.
6. Hardened deployment succeeds. Verify: HTTP 403 with rule 110013, public S3 read still works, restricted direct read returns AccessDenied and joins to rule 110031.
7. Capture sanitized evidence for the talk.
8. Destroy Lab + PURGE completes; verify no lab EC2/VPC/buckets remain. Bootstrap resources are the documented retention exception.

If one of these gates fails, keep the failed outcome visible and investigate using the operations guide. Do not replace missing live evidence with synthetic fixtures presented as real findings.
