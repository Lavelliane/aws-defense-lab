terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = {
      source = "hashicorp/aws", version = "~> 6.0"
    }
  }
  backend "s3" {
  }
}
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project = "aws-defense-lab", Lab = var.lab_name, ManagedBy = "Terraform"
    }
  }
}
data "aws_caller_identity" "current" {
}
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
locals {
  prefix      = "${var.lab_name}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  bundle_path = "${path.module}/../.build/lab.zip"
  bundle_sha  = filesha256(local.bundle_path)
  role_path   = "/aws-defense-lab/"
}
