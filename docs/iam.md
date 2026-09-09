# IAM responsibilities and trust

| Identity | Permissions |
|---|---|
| Human bootstrap operator | Existing authorized identity capable of creating IAM/OIDC and state S3 resources |
| GitHub deployment role | Create/update/delete the lab; scoped S3, IAM paths, CloudTrail ARN and tagged SSM targets |
| Application role | Read bundle and dummy objects; hardened mode restricts the latter to public/* |
| Wazuh role | Read audit objects and bundle; list audit bucket; SSM host-channel permissions |

Both runtime roles carry the bootstrap permissions boundary. It caps them at read access to lab buckets plus SSM managed-instance channels. The deployment role cannot modify this boundary, change itself, remove runtime boundaries, or create access keys/users. IAM role attachment is restricted to AmazonSSMManagedInstanceCore; passing runtime roles is restricted to EC2.

EC2 mutations and destruction require matching `Lab` and `Project` resource tags in the configured region. Existing untagged resources cannot be retagged into the lab. New network resources require lab tags; instance launches are restricted to t3.micro/t3.xlarge and tagged lab subnets/security groups. Launch-supporting images, volumes and interfaces need separate resource permissions. Read-only discovery remains region-wide.

This is still a provisioning identity with substantial authority over tagged lab resources, not a general production deployment framework. Use a dedicated lab account and trusted repository maintainers. AWS authorization must be verified in that account before reuse; tags and the runtime-role permissions boundary do not impose a spending cap.

CloudTrail records account management events across regions. It records GetObject data events only for the dummy-data bucket, avoiding recursive telemetry on its own audit objects. Management events can include activity unrelated to this lab if you deploy in a shared account, which is another reason to isolate the account.

No IAM users or static access keys are created. An IAM-user compromise scenario was discussed as optional and is intentionally outside this single-chain version. It is not required for the demo.
