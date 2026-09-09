mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock-lab-bucket", id = "mock-lab-bucket" }
  }
  mock_resource "aws_instance" {
    defaults = { private_ip = "10.77.1.10", public_ip = "203.0.113.10" }
  }
}
variables {
  allowed_cidr             = "203.0.113.10/32"
  permissions_boundary_arn = "arn:aws:iam::123456789012:policy/aws-defense-lab/defense-lab-boundary"
}
run "vulnerable_lab" {
  command = apply
  assert {
    condition     = aws_instance.app.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must remain enabled even in vulnerable mode."
  }
  assert {
    condition     = aws_instance.manager.instance_type == "t3.xlarge"
    error_message = "Manager must have resources for the all-in-one Wazuh install."
  }
  assert {
    condition     = alltrue([for b in aws_s3_bucket_public_access_block.lab : b.block_public_policy && b.restrict_public_buckets])
    error_message = "All lab buckets must block public access."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.app.policy).Statement[0].Resource == "${aws_s3_bucket.lab["data"].arn}/*"
    error_message = "Vulnerable role reads dummy bucket only."
  }
  assert {
    condition     = aws_iam_role.app.permissions_boundary == var.permissions_boundary_arn
    error_message = "Application role requires bootstrap boundary."
  }
}
run "hardened_lab" {
  command = apply
  variables {
    app_mode = "hardened"
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.app.policy).Statement[0].Resource == "${aws_s3_bucket.lab["data"].arn}/public/*"
    error_message = "Hardened role must permit only public objects."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.app.policy).Statement[1].Effect == "Deny"
    error_message = "Restricted prefix must be explicitly denied."
  }
}
run "reject_public_access" {
  command = plan
  variables {
    allowed_cidr = "0.0.0.0/0"
  }
  expect_failures = [var.allowed_cidr]
}
run "reject_unknown_mode" {
  command = plan
  variables {
    app_mode = "production"
  }
  expect_failures = [var.app_mode]
}
