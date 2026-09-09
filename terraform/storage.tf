resource "aws_s3_bucket" "lab" {
  for_each      = toset(["data", "audit", "assets"])
  bucket        = "${local.prefix}-${each.key}"
  force_destroy = var.purge_on_destroy
}
resource "aws_s3_bucket_public_access_block" "lab" {
  for_each                = aws_s3_bucket.lab
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "lab" {
  for_each = aws_s3_bucket.lab
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  for_each = aws_s3_bucket.lab
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_policy" "lab" {
  for_each = aws_s3_bucket.lab
  bucket   = each.value.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = concat([
      {
        Sid      = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
        Resource = [each.value.arn, "${each.value.arn}/*"],
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
      ], each.key == "audit" ? [
      {
        Sid = "CloudTrailAcl", Effect = "Allow", Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "s3:GetBucketAcl", Resource = each.value.arn,
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.lab_name}"
          }
        }
      },
      {
        Sid = "CloudTrailWrite", Effect = "Allow", Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "s3:PutObject", Resource = "${each.value.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control",
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.lab_name}"
          }
        }
      }
    ] : [])
    }
  )
}
resource "aws_s3_object" "dummy" {
  for_each = {
    "public/report.csv"      = file("${path.module}/../app/dummy-data/public/report.csv")
    "restricted/finance.csv" = file("${path.module}/../app/dummy-data/restricted/finance.csv")
  }
  bucket       = aws_s3_bucket.lab["data"].id
  key          = each.key
  content      = each.value
  content_type = "text/csv"
  depends_on   = [aws_s3_bucket_versioning.lab]
}
resource "aws_s3_object" "bundle" {
  bucket       = aws_s3_bucket.lab["assets"].id
  key          = "bundles/${local.bundle_sha}.zip"
  source       = local.bundle_path
  source_hash  = local.bundle_sha
  content_type = "application/zip"
  depends_on   = [aws_s3_bucket_versioning.lab]
}
resource "aws_cloudtrail" "lab" {
  name                          = var.lab_name
  s3_bucket_name                = aws_s3_bucket.lab["audit"].id
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = true
  advanced_event_selector {
    name = "Management activity"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
  advanced_event_selector {
    name = "Dummy data reads only"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.lab["data"].arn}/"]
    }
    field_selector {
      field  = "eventName"
      equals = ["GetObject"]
    }
  }
  depends_on = [aws_s3_bucket_policy.lab]
}
