# Primary technical references

References checked during implementation on 2026-09-09. Installed-package inspection also informed the Wazuh launcher and CLI checks.

- [Wazuh quickstart and all-in-one sizing](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh AWS CloudTrail integration](https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudtrail.html)
- [Wazuh AWS authentication with EC2 IAM roles](https://documentation.wazuh.com/current/cloud-security/amazon/services/prerequisites/credentials.html)
- [Wazuh CDB indicator matching](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)
- [Wazuh custom detection rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh 4.14.7 AWS base rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0350-amazon_rules.xml)
- [CloudTrail data events must be explicitly enabled](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail asynchronous delivery](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)
- [GitHub Actions AWS OIDC](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [Manual GitHub workflows](https://docs.github.com/actions/managing-workflow-runs/manually-running-a-workflow)
- [Terraform S3 backend and locking](https://developer.hashicorp.com/terraform/language/backend/s3)
- [Terraform mock providers](https://developer.hashicorp.com/terraform/language/tests/mocking)
- [EC2 IAM action/resource/condition reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)
- [EC2 tagging on creation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html)

The Wazuh 4.14.7 package uses a shell launcher at `wodles/aws/aws-s3` and includes its own Python environment. The repository preserves this wrapper. An older instruction to replace the launcher's shebang is not appropriate for that package layout.
