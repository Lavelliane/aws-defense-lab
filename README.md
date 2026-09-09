# AWS Defense Lab

A reproducible Terraform lab for a **35-minute recorded attack-and-defense walkthrough**: a vulnerable EC2 export application, Wazuh, CloudTrail, synthetic IP threat intelligence, bounded attacker scripts, and a verified hardening scenario.

**Build status:** source implemented and locally tested. No AWS infrastructure has been deployed from this build. Provider-schema/mock Terraform execution and live Wazuh/CloudTrail integration still require the included CI/runtime gates. See [validation status](docs/validation.md) before deploying.

## What you get

| Path | Deliverable |
|---|---|
| `bootstrap/` | One-time OIDC trust, deployment role, runtime IAM boundary and S3 state backend |
| `terraform/` | Two EC2 hosts, isolated lab network, IAM roles, private buckets, CloudTrail and artifact delivery |
| `app/` | Fixed dummy export application with vulnerable and hardened modes |
| `wazuh/` | Custom behavioral, cloud and synthetic-IOC detection rules |
| `threat-intel/` | Validated indicator importer with expiration and atomic CDB updates |
| `scenarios/` | Bounded probe, export-abuse and prevention-verification scripts |
| `scripts/` | Installers, readiness, IAM verification, evidence correlation and bundle builder |
| `.github/workflows/` | Validate, Deploy Lab, Run Lab Scenario, and Destroy Lab workflows |
| `tests/` | Application, HTTP adapter, scenario, indicator, config, evidence and IAM policy tests |
| `docs/` | Architecture, setup, IAM, costs, troubleshooting, validation and 35-minute talk outline |
| `evidence/` | Capture instructions; no fabricated live screenshots or logs |

The core demonstration is **restricted dummy export → app event → CloudTrail GetObject → Wazuh alert with synthetic IOC context → authorization and IAM fix → verified denial**. This is a purpose-built application, not a fork of AWSGoat. No IAM users or long-lived AWS access keys are created.

## Start here

1. Put this source in your GitHub repository with default branch **main**.
2. Follow [one-time setup](docs/operations.md#one-time-setup) using an existing authorized AWS identity.
3. Set the emitted GitHub repository variables and your allowed public IPv4 `/32`.
4. Run **Actions → Deploy Lab → vulnerable**.
5. Run **Run Lab Scenario → exploit** and capture the verified alerts.
6. Deploy **hardened**, then run **verify**.
7. Save your presentation evidence and run **Destroy Lab** with the explicit PURGE confirmation.

After bootstrap, deployment is one manual workflow launch. It waits for readiness and leaves the attack as a separate action. Setup does not use CloudFormation. Use a dedicated AWS lab account; read the [cost footprint](docs/costs-and-troubleshooting.md) and [IAM scope](docs/iam.md).

## Local tests

These tests need Python 3.10+ and no AWS credentials:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build_bundle.py
```

With Terraform installed, `make validate` also checks HCL formatting, provider schemas, and mocked infrastructure tests. `terraform test` in this repository uses a mock AWS provider and does not create AWS resources. GitHub's validation workflow runs the same gates without AWS authentication.

The runtime rule test is `scripts/test_wazuh_rules.py`; manager provisioning runs it against the installed Wazuh engine. The later scenario gate checks actual telemetry delivery and exact S3 request-ID correlation.

## Read more

- [Architecture and rule map](docs/architecture.md)
- [Deployment, dashboard access, scenarios and teardown](docs/operations.md)
- [IAM roles and trust](docs/iam.md)
- [Costs and troubleshooting](docs/costs-and-troubleshooting.md)
- [35-minute talk and capture checklist](docs/talk-35-minutes.md)
- [Verification results and remaining gates](docs/validation.md)
- [Primary technical references](docs/references.md)

Built for teaching and controlled exercises. The HTTP application deliberately contains an authorization flaw in vulnerable mode and handles only synthetic data. Do not adapt it into a real customer-facing service.
