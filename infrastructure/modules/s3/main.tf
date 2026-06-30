locals {
  common_config = {
    versioning = true
    sse        = "aws:kms"
  }
}

# ── Staging Bucket ────────────────────────────────────────────────────────

resource "aws_s3_bucket" "staging" {
  bucket = var.bucket_names["staging"]
  tags = {
    Name        = var.bucket_names["staging"]
    Environment = var.environment
    Zone        = "staging"
  }
}

resource "aws_s3_bucket_versioning" "staging" {
  bucket = aws_s3_bucket.staging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.staging_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "staging" {
  bucket                  = aws_s3_bucket.staging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "staging" {
  bucket = aws_s3_bucket.staging.id
  rule {
    id     = "expire-after-30-days"
    status = "Enabled"
    expiration {
      days = 30
    }
    filter {}
  }
}

resource "aws_s3_bucket_logging" "staging" {
  bucket        = aws_s3_bucket.staging.id
  target_bucket = var.bucket_names["logging"]
  target_prefix = "s3-access/staging/"
}

resource "aws_s3_bucket_policy" "staging" {
  bucket = aws_s3_bucket.staging.id
  policy = data.aws_iam_policy_document.staging.json
}

data "aws_iam_policy_document" "staging" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.staging.arn,
      "${aws_s3_bucket.staging.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ── Clean Bucket ──────────────────────────────────────────────────────────

resource "aws_s3_bucket" "clean" {
  bucket = var.bucket_names["clean"]
  tags = {
    Name        = var.bucket_names["clean"]
    Environment = var.environment
    Zone        = "clean"
  }
}

resource "aws_s3_bucket_versioning" "clean" {
  bucket = aws_s3_bucket.clean.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "clean" {
  bucket = aws_s3_bucket.clean.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.clean_key_arn != "" ? var.clean_key_arn : var.staging_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "clean" {
  bucket                  = aws_s3_bucket.clean.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "clean" {
  bucket        = aws_s3_bucket.clean.id
  target_bucket = var.bucket_names["logging"]
  target_prefix = "s3-access/clean/"
}

# ── Quarantine Bucket ─────────────────────────────────────────────────────

resource "aws_s3_bucket" "quarantine" {
  bucket              = var.bucket_names["quarantine"]
  object_lock_enabled = true
  tags = {
    Name        = var.bucket_names["quarantine"]
    Environment = var.environment
    Zone        = "quarantine"
  }
}

resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.quarantine_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket                  = aws_s3_bucket.quarantine.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 2555
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  rule {
    id     = "expire-after-7-years"
    status = "Enabled"
    expiration {
      days = 2555
    }
    filter {}
  }
}

resource "aws_s3_bucket_logging" "quarantine" {
  bucket        = aws_s3_bucket.quarantine.id
  target_bucket = var.bucket_names["logging"]
  target_prefix = "s3-access/quarantine/"
}

resource "aws_s3_bucket_policy" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  policy = data.aws_iam_policy_document.quarantine.json
  depends_on = [
    aws_s3_bucket_object_lock_configuration.quarantine,
    aws_s3_bucket_versioning.quarantine,
  ]
}

data "aws_iam_policy_document" "quarantine" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.quarantine.arn,
      "${aws_s3_bucket.quarantine.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ── Reports Bucket ────────────────────────────────────────────────────────

resource "aws_s3_bucket" "reports" {
  bucket = var.bucket_names["reports"]
  tags = {
    Name        = var.bucket_names["reports"]
    Environment = var.environment
    Zone        = "reports"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.clean_key_arn != "" ? var.clean_key_arn : var.staging_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "glacier-after-30-days"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    filter {}
  }
}

resource "aws_s3_bucket_logging" "reports" {
  bucket        = aws_s3_bucket.reports.id
  target_bucket = var.bucket_names["logging"]
  target_prefix = "s3-access/reports/"
}

# ── Logging Bucket ────────────────────────────────────────────────────────

resource "aws_s3_bucket" "logging" {
  bucket = var.bucket_names["logging"]
  tags = {
    Name        = var.bucket_names["logging"]
    Environment = var.environment
    Zone        = "logging"
  }
}

resource "aws_s3_bucket_versioning" "logging" {
  bucket = aws_s3_bucket.logging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logging" {
  bucket                  = aws_s3_bucket.logging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id
  rule {
    id     = "expire-after-90-days"
    status = "Enabled"
    expiration {
      days = 90
    }
    filter {}
  }
}

resource "aws_s3_bucket_ownership_controls" "logging" {
  bucket = aws_s3_bucket.logging.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# ── CloudTrail Bucket ─────────────────────────────────────────────────────

resource "aws_s3_bucket" "cloudtrail" {
  bucket = var.bucket_names["cloudtrail"]
  tags = {
    Name        = var.bucket_names["cloudtrail"]
    Environment = var.environment
    Zone        = "audit"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    id     = "expire-after-2555-days"
    status = "Enabled"
    expiration {
      days = 2555
    }
    filter {}
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail.json
}

data "aws_iam_policy_document" "cloudtrail" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
