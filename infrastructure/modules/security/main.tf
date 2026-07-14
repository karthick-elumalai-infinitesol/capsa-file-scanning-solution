# ============================================================================
# KMS Keys — one per security zone
# ============================================================================

resource "aws_kms_key" "staging" {
  description             = "KMS key for CAPSA staging bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_staging.json
  tags = {
    Name        = "capsa-staging-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "staging" {
  name          = var.kms_alias_names["staging"]
  target_key_id = aws_kms_key.staging.key_id
}

data "aws_iam_policy_document" "kms_staging" {
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "clean" {
  description             = "KMS key for CAPSA clean bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = {
    Name        = "capsa-clean-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "clean" {
  name          = var.kms_alias_names["clean"]
  target_key_id = aws_kms_key.clean.key_id
}

resource "aws_kms_key" "quarantine" {
  description             = "KMS key for CAPSA quarantine bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_quarantine.json
  tags = {
    Name        = "capsa-quarantine-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "quarantine" {
  name          = var.kms_alias_names["quarantine"]
  target_key_id = aws_kms_key.quarantine.key_id
}

data "aws_iam_policy_document" "kms_quarantine" {
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

# ============================================================================
# Secrets Manager — SFTPGo Admin Password
# ============================================================================

resource "aws_secretsmanager_secret" "sftpgo_admin" {
  name                    = "capsa/sftpgo-admin-password"
  description             = "SFTPGo admin password for REST API authentication"
  recovery_window_in_days = 0
  tags = {
    Name        = "capsa-sftpgo-admin-password"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "sftpgo_admin" {
  secret_id     = aws_secretsmanager_secret.sftpgo_admin.id
  secret_string = var.sftpgo_admin_password
}

# ============================================================================
# GuardDuty
# ============================================================================

resource "aws_guardduty_detector" "main" {
  count  = var.guardduty_enable ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}


