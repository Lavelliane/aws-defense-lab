locals {
  ec2_trust = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "ec2.amazonaws.com"
      }, Action = "sts:AssumeRole"
      }
    ]
    }
  )
}
resource "aws_iam_role" "app" {
  name                 = "${var.lab_name}-app"
  path                 = local.role_path
  assume_role_policy   = local.ec2_trust
  permissions_boundary = var.permissions_boundary_arn
}
resource "aws_iam_role" "manager" {
  name                 = "${var.lab_name}-manager"
  path                 = local.role_path
  assume_role_policy   = local.ec2_trust
  permissions_boundary = var.permissions_boundary_arn
}
resource "aws_iam_instance_profile" "app" {
  name = "${var.lab_name}-app"
  path = local.role_path
  role = aws_iam_role.app.name
}
resource "aws_iam_instance_profile" "manager" {
  name = "${var.lab_name}-manager"
  path = local.role_path
  role = aws_iam_role.manager.name
}
resource "aws_iam_role_policy_attachment" "ssm" {
  for_each = {
    app = aws_iam_role.app.name, manager = aws_iam_role.manager.name
  }
  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy" "app" {
  name = "dummy-data-and-bundle"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = concat([
      {
        Sid      = "ReadDummyData", Effect = "Allow", Action = "s3:GetObject",
        Resource = var.app_mode == "vulnerable" ? "${aws_s3_bucket.lab["data"].arn}/*" : "${aws_s3_bucket.lab["data"].arn}/public/*"
      }
      ], var.app_mode == "hardened" ? [
      {
        Sid = "DenyRestrictedData", Effect = "Deny", Action = "s3:GetObject", Resource = "${aws_s3_bucket.lab["data"].arn}/restricted/*"
      }
      ] : [], [
      {
        Sid = "ReadBundle", Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.lab["assets"].arn}/bundles/*"
      }
    ])
    }
  )
}
resource "aws_iam_role_policy" "manager" {
  name = "audit-and-bundle"
  role = aws_iam_role.manager.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketLocation"], Resource = aws_s3_bucket.lab["audit"].arn
      },
      {
        Effect = "Allow", Action = "s3:GetObject", Resource = ["${aws_s3_bucket.lab["audit"].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*", "${aws_s3_bucket.lab["assets"].arn}/bundles/*"]
      }
    ]
    }
  )
}
