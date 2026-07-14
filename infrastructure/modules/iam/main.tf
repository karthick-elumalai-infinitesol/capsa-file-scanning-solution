locals {
  # Construct Lambda ARN from function name to avoid circular deps
  routing_lambda_arn       = "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:${var.function_names["routing"]}"
  capsa_lambda_arn_pattern = "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:${var.function_names["routing"]}"
}

# ============================================================================
# LAMBDA: File Scan Trigger Role
# ============================================================================

resource "aws_iam_role" "scan_trigger" {
  name = var.role_names["scan_trigger"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["scan_trigger"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "scan_trigger" {
  name   = "${var.role_names["scan_trigger"]}-policy"
  role   = aws_iam_role.scan_trigger.id
  policy = data.aws_iam_policy_document.scan_trigger.json
}

data "aws_iam_policy_document" "scan_trigger" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }

  statement {
    sid    = "S3StagingRead"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
    ]
    resources = [
      var.staging_bucket_arn,
      "${var.staging_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "S3StagingTagAndCopy"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:CopyObject",
    ]
    resources = ["${var.staging_bucket_arn}/*"]
  }

  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.staging_key_arn, var.quarantine_key_arn]
  }

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid       = "InvokeRoutingLambda"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [local.routing_lambda_arn]
  }

  statement {
    sid    = "GuardDutyLookup"
    effect = "Allow"
    actions = [
      "guardduty:ListDetectors",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "SecretsManager"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:capsa/*"]
  }

  dynamic "statement" {
    for_each = var.enable_vpc ? [1] : []
    content {
      sid    = "EC2Networking"
      effect = "Allow"
      actions = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses",
      ]
      resources = ["*"]
    }
  }
}

# ============================================================================
# LAMBDA: Routing Engine Role
# ============================================================================

resource "aws_iam_role" "scan_engine" {
  name = var.role_names["scan_engine"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["scan_engine"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "scan_engine" {
  name   = "${var.role_names["scan_engine"]}-policy"
  role   = aws_iam_role.scan_engine.id
  policy = data.aws_iam_policy_document.scan_engine.json
}

data "aws_iam_policy_document" "scan_engine" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }

  statement {
    sid       = "S3StagingRead"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.staging_bucket_arn}/*"]
  }

  statement {
    sid    = "S3StagingWrite"
    effect = "Allow"
    actions = [
      "s3:PutObjectTagging",
      "s3:DeleteObject",
    ]
    resources = ["${var.staging_bucket_arn}/*"]
  }

  statement {
    sid    = "S3CleanWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:CopyObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${var.clean_bucket_arn}/*"]
  }

  statement {
    sid    = "S3QuarantineWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${var.quarantine_bucket_arn}/*"]
  }

  statement {
    sid    = "S3ReportsWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      var.reports_bucket_arn,
      "${var.reports_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "KMSOperations"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = compact([var.staging_key_arn, var.clean_key_arn, var.quarantine_key_arn])
  }

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid    = "GuardDutyLookup"
    effect = "Allow"
    actions = [
      "guardduty:ListDetectors",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "SecretsManager"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:capsa/*"]
  }

  dynamic "statement" {
    for_each = var.enable_vpc ? [1] : []
    content {
      sid    = "EC2Networking"
      effect = "Allow"
      actions = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses",
      ]
      resources = ["*"]
    }
  }
}

# ============================================================================
# LAMBDA: Report Generator Role
# ============================================================================

resource "aws_iam_role" "report_generator" {
  name = var.role_names["report_generator"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["report_generator"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "report_generator" {
  name   = "${var.role_names["report_generator"]}-policy"
  role   = aws_iam_role.report_generator.id
  policy = data.aws_iam_policy_document.report_generator.json
}

data "aws_iam_policy_document" "report_generator" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }

  statement {
    sid    = "ReportsBucketAccess"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      var.reports_bucket_arn,
      "${var.reports_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "ReadScanBuckets"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      var.staging_bucket_arn,
      var.clean_bucket_arn,
      var.quarantine_bucket_arn,
    ]
  }

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid    = "KMSReports"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = compact([var.clean_key_arn, var.staging_key_arn])
  }
}

# ============================================================================
# ECS Task Execution Role
# ============================================================================

resource "aws_iam_role" "ecs_task_execution" {
  name = var.role_names["ecs_execution"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["ecs_execution"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_task_execution_ecr" {
  name = "${var.role_names["ecs_execution"]}-ecr-policy"
  role = aws_iam_role.ecs_task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ECRAuth"
      Effect = "Allow"
      Action = [
        "ecr:GetAuthorizationToken",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
      ]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task_execution_secrets" {
  name = "${var.role_names["ecs_execution"]}-secrets-policy"
  role = aws_iam_role.ecs_task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SecretsManagerRead"
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
      ]
      Resource = ["arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:capsa/*"]
    }]
  })
}

# ============================================================================
# ECS Task Role (for ClamAV + Queue Worker in ECS)
# ============================================================================

resource "aws_iam_role" "ecs_task" {
  name = var.role_names["ecs_task"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["ecs_task"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "ecs_task" {
  name   = "${var.role_names["ecs_task"]}-policy"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task.json
}

data "aws_iam_policy_document" "ecs_task" {
  statement {
    sid    = "S3StagingRead"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
    ]
    resources = [
      "${var.staging_bucket_arn}",
      "${var.staging_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "S3CleanWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:CopyObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${var.clean_bucket_arn}/*"]
  }

  statement {
    sid    = "S3QuarantineWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${var.quarantine_bucket_arn}/*"]
  }

  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]
    resources = [var.staging_key_arn, var.quarantine_key_arn]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }

  statement {
    sid       = "InvokeRoutingLambda"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [local.routing_lambda_arn]
  }

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }
}

# ============================================================================
# Migration Team IAM Role
# ============================================================================

resource "aws_iam_role" "migration_team" {
  name = "capsa-migration-team"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
    }]
  })
  tags = {
    Name        = "capsa-migration-team"
    Environment = var.environment
  }
}

# ============================================================================
# SFTPGo ECS Task Role — writes partner uploads to staging bucket
# ============================================================================

resource "aws_iam_role" "sftpgo" {
  name = var.role_names["sftpgo"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = {
    Name        = var.role_names["sftpgo"]
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "sftpgo" {
  name   = "${var.role_names["sftpgo"]}-policy"
  role   = aws_iam_role.sftpgo.id
  policy = data.aws_iam_policy_document.sftpgo.json
}

data "aws_iam_policy_document" "sftpgo" {
  statement {
    sid    = "S3StagingWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject",
    ]
    resources = [
      var.staging_bucket_arn,
      "${var.staging_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "KMSEncryptDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.staging_key_arn]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }
}

resource "aws_iam_role_policy" "migration_team" {
  name = "capsa-migration-team-policy"
  role = aws_iam_role.migration_team.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StagingWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetObject",
        ]
        Resource = ["${var.staging_bucket_arn}/*"]
      },
      {
        Sid    = "StagingList"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [var.staging_bucket_arn]
      },
      {
        Sid    = "KMSEncrypt"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = [var.staging_key_arn]
      },
    ]
  })
}

# ============================================================================
# Security Team Read-Only Role
# ============================================================================

resource "aws_iam_role" "security_team" {
  name = "capsa-security-team-readonly"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
    }]
  })
  tags = {
    Name        = "capsa-security-team-readonly"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "security_team" {
  name = "capsa-security-team-readonly-policy"
  role = aws_iam_role.security_team.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "QuarantineRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          var.quarantine_bucket_arn,
          "${var.quarantine_bucket_arn}/*",
        ]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = [var.quarantine_key_arn]
      },
      {
        Sid    = "SecurityHubRead"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:ListFindings",
        ]
        Resource = ["*"]
      },
      {
        Sid    = "CloudWatchRead"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "logs:FilterLogEvents",
        ]
        Resource = ["*"]
      },
    ]
  })
}
