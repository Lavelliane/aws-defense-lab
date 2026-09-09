terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = {
      source = "hashicorp/aws", version = "~> 6.0"
    }
  }
}
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project = "aws-defense-lab-bootstrap", Lab = var.lab_name
    }
  }
}
data "aws_caller_identity" "current" {
}
locals {
  account          = data.aws_caller_identity.current.account_id
  prefix           = "${var.lab_name}-${local.account}-${var.aws_region}"
  github_subject   = "repo:${var.github_repository}:ref:refs/heads/main"
  buckets          = [for suffix in ["data", "audit", "assets"] : "arn:aws:s3:::${local.prefix}-${suffix}"]
  lab_roles        = "arn:aws:iam::${local.account}:role/aws-defense-lab/${var.lab_name}-*"
  lab_profiles     = "arn:aws:iam::${local.account}:instance-profile/aws-defense-lab/${var.lab_name}-*"
  ssm_core_actions = ["ssm:DescribeAssociation", "ssm:GetDeployablePatchSnapshotForInstance", "ssm:GetDocument", "ssm:DescribeDocument", "ssm:GetManifest", "ssm:ListAssociations", "ssm:ListInstanceAssociations", "ssm:PutInventory", "ssm:PutComplianceItems", "ssm:PutConfigurePackageResult", "ssm:UpdateAssociationStatus", "ssm:UpdateInstanceAssociationStatus", "ssm:UpdateInstanceInformation", "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel", "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage", "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply"]
}
resource "aws_s3_bucket" "state" {
  bucket        = "${local.prefix}-state"
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"], Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
      }
    ]
    }
  )
}
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.existing_oidc_provider_arn == "" ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
resource "aws_iam_policy" "boundary" {
  name        = "${var.lab_name}-boundary"
  path        = "/aws-defense-lab/"
  description = "Maximum runtime permissions; deployment role cannot modify this policy."
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Sid = "LabObjectsOnly", Effect = "Allow", Action = "s3:GetObject", Resource = [for arn in local.buckets : "${arn}/*"]
      },
      {
        Sid = "LabBucketMetadata", Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketLocation"], Resource = local.buckets
      },
      {
        Sid = "ManagedHostChannels", Effect = "Allow", Action = local.ssm_core_actions, Resource = "*"
      }
    ]
    }
  )
}
resource "aws_iam_role" "deploy" {
  name                 = "${var.lab_name}-github-deploy"
  path                 = "/aws-defense-bootstrap/"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow",
      Principal = {
        Federated = var.existing_oidc_provider_arn != "" ? var.existing_oidc_provider_arn : aws_iam_openid_connect_provider.github[0].arn
      },
      Action = "sts:AssumeRoleWithWebIdentity", Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub" = local.github_subject
        }
      }
      }
    ]
    }
  )
}
resource "aws_iam_role_policy" "deploy" {
  name = "lab-deployment"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = concat(jsondecode(templatefile("${path.module}/ec2-policy.json.tftpl", { region = var.aws_region, account = local.account, lab_name = var.lab_name })), [
      {
        Sid = "StateList", Effect = "Allow", Action = "s3:ListBucket", Resource = aws_s3_bucket.state.arn
      },
      {
        Sid = "StateReadWrite", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${aws_s3_bucket.state.arn}/lab/terraform.tfstate", "${aws_s3_bucket.state.arn}/lab/terraform.tfstate.tflock"]
      },
      {
        Sid = "StateUnlock", Effect = "Allow", Action = "s3:DeleteObject", Resource = "${aws_s3_bucket.state.arn}/lab/terraform.tfstate.tflock"
      },
      {
        Sid = "LabStorage", Effect = "Allow", Action = "s3:*", Resource = concat(local.buckets, [for arn in local.buckets : "${arn}/*"])
      },
      {
        Sid = "CreateBoundedRoles", Effect = "Allow", Action = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"], Resource = local.lab_roles,
        Condition = {
          StringEquals = {
            "iam:PermissionsBoundary" = aws_iam_policy.boundary.arn
          }
        }
      },
      {
        Sid = "ManageLabRoles", Effect = "Allow", Action = ["iam:GetRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:ListAttachedRolePolicies", "iam:TagRole", "iam:UntagRole", "iam:ListInstanceProfilesForRole"], Resource = local.lab_roles
      },
      {
        Sid = "AttachSSMOnly", Effect = "Allow", Action = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"], Resource = local.lab_roles,
        Condition = {
          ArnEquals = {
            "iam:PolicyARN" = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
          }
        }
      },
      {
        Sid = "Profiles", Effect = "Allow", Action = ["iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile"], Resource = local.lab_profiles
      },
      {
        Sid = "PassLabRolesToEC2", Effect = "Allow", Action = "iam:PassRole", Resource = local.lab_roles,
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      },
      {
        Sid = "Trail", Effect = "Allow", Action = ["cloudtrail:CreateTrail", "cloudtrail:UpdateTrail", "cloudtrail:DeleteTrail", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors", "cloudtrail:PutEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:ListTags", "cloudtrail:AddTags", "cloudtrail:RemoveTags"], Resource = "arn:aws:cloudtrail:${var.aws_region}:${local.account}:trail/${var.lab_name}"
      },
      {
        Sid = "DescribeTrails", Effect = "Allow", Action = "cloudtrail:DescribeTrails", Resource = "*"
      },
      {
        Sid = "RunLabCommands", Effect = "Allow", Action = "ssm:SendCommand", Resource = "arn:aws:ec2:${var.aws_region}:${local.account}:instance/*",
        Condition = {
          StringEquals = {
            "ssm:resourceTag/Lab" = var.lab_name, "ssm:resourceTag/Project" = "aws-defense-lab"
          }
        }
      },
      {
        Sid = "RunShellDocument", Effect = "Allow", Action = "ssm:SendCommand", Resource = "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"
      },
      {
        Sid = "ReadCommandResults", Effect = "Allow", Action = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:DescribeInstanceInformation"], Resource = "*"
      }
    ])
    }
  )
}
