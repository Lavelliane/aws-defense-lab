output "github_variables" {
  value = {
    AWS_ROLE_ARN             = aws_iam_role.deploy.arn, AWS_REGION = var.aws_region,
    TF_STATE_BUCKET          = aws_s3_bucket.state.id, LAB_NAME = var.lab_name,
    PERMISSIONS_BOUNDARY_ARN = aws_iam_policy.boundary.arn
  }
}
output "backend" {
  value = {
    bucket = aws_s3_bucket.state.id, key = "lab/terraform.tfstate", region = var.aws_region, encrypt = true, use_lockfile = true
  }
}
