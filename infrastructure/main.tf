# ============================================================================
# CAPSA — OpenSecOps Analyzer
# Root module: wires all child modules together
#
# Architecture:
#   S3 → Lambda(scan_trigger) → Redis (ECS) → ClamAV (ECS) → Lambda(routing)
#                                                    → S3(clean|quarantine)
# ============================================================================

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ── SNS Topic (root-level to avoid circular deps) ────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name = "capsa-security-alerts"
  tags = {
    Name        = "capsa-security-alerts"
    Environment = var.environment
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaAndGuardDuty"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "guardduty.amazonaws.com",
            "cloudtrail.amazonaws.com",
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
    ]
  })
}

# ── Naming Convention ─────────────────────────────────────────────────────

module "naming" {
  source = "./modules/naming"

  application = "capsa"
  environment = var.environment
  account_id  = local.account_id
}

# ── Networking ────────────────────────────────────────────────────────────

module "networking" {
  source = "./modules/networking"

  environment                 = var.environment
  vpc_id                      = var.vpc_id
  subnet_ids                  = var.subnet_ids
  security_group_ids          = var.security_group_ids
  route_table_ids             = var.route_table_ids
  service_discovery_namespace = module.naming.service_discovery_namespace
  clamav_port                 = var.clamav_port
}

# ── Security (KMS keys, GuardDuty) ──────────────────────────────────────

module "security" {
  source = "./modules/security"

  environment      = var.environment
  bucket_names     = module.naming.s3_bucket
  kms_alias_names  = module.naming.kms_alias
  sns_topic_arn    = aws_sns_topic.security_alerts.arn
  aws_account_id   = local.account_id
  guardduty_enable = true
}

# ── S3 Buckets ────────────────────────────────────────────────────────────

module "s3" {
  source = "./modules/s3"

  environment        = var.environment
  bucket_names       = module.naming.s3_bucket
  staging_key_arn    = module.security.staging_key_arn
  clean_key_arn      = module.security.clean_key_arn
  quarantine_key_arn = module.security.quarantine_key_arn
}

# ── IAM Roles & Policies ──────────────────────────────────────────────────

module "iam" {
  source = "./modules/iam"

  environment           = var.environment
  role_names            = module.naming.iam_role
  function_names        = module.naming.lambda_function
  staging_bucket_arn    = module.s3.staging_bucket_arn
  clean_bucket_arn      = module.s3.clean_bucket_arn
  quarantine_bucket_arn = module.s3.quarantine_bucket_arn
  reports_bucket_arn    = module.s3.reports_bucket_arn
  staging_key_arn       = module.security.staging_key_arn
  clean_key_arn         = module.security.clean_key_arn
  quarantine_key_arn    = module.security.quarantine_key_arn
  sns_topic_arn         = aws_sns_topic.security_alerts.arn
  aws_region            = var.aws_region
  aws_account_id        = local.account_id
  enable_vpc            = length(var.subnet_ids) > 0
}

# ── Lambda Functions ──────────────────────────────────────────────────────

module "lambda" {
  source = "./modules/lambda"

  environment                = var.environment
  function_names             = module.naming.lambda_function
  log_group_names            = module.naming.cloudwatch_log
  scan_trigger_role_arn      = module.iam.scan_trigger_role_arn
  scan_engine_role_arn       = module.iam.scan_engine_role_arn
  report_generator_role_arn  = module.iam.report_generator_role_arn
  staging_bucket_id          = module.s3.staging_bucket_id
  clean_bucket_id            = module.s3.clean_bucket_id
  quarantine_bucket_id       = module.s3.quarantine_bucket_id
  reports_bucket_id          = module.s3.reports_bucket_id
  sns_topic_arn              = aws_sns_topic.security_alerts.arn
  guardduty_detector_id      = module.security.guardduty_detector_id
  guardduty_lookback_minutes = var.guardduty_findings_lookback_minutes
  routing_lambda_name        = module.naming.lambda_function["routing"]
  subnet_ids                 = module.networking.subnet_ids
  security_group_ids         = module.networking.security_group_ids
  lambda_timeout             = var.lambda_timeout
  lambda_memory              = var.lambda_memory
  redis_url                  = var.redis_url
  jira_url                   = var.jira_url
  jira_username              = var.jira_username
  jira_project_key           = var.jira_project_key
  aws_region                 = var.aws_region
}

# ── S3 Bucket Notification (to scan_trigger Lambda) ──────────────────────
# Defined here to avoid circular dep between s3 <> lambda modules

resource "aws_lambda_permission" "staging_bucket_invoke_scan_trigger" {
  statement_id  = "AllowS3InvokeScanTrigger"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.scan_trigger_function_arn
  principal     = "s3.amazonaws.com"
  source_arn    = module.s3.staging_bucket_arn
}

resource "aws_s3_bucket_notification" "staging_to_lambda" {
  bucket = module.s3.staging_bucket_id

  lambda_function {
    lambda_function_arn = module.lambda.scan_trigger_function_arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.staging_bucket_invoke_scan_trigger]
}

# ── CloudTrail (depends on S3 bucket + policy existing) ──────────────────

resource "aws_cloudtrail" "main" {
  count                         = var.cloudtrail_enable ? 1 : 0
  name                          = "capsa-cloudtrail"
  s3_bucket_name                = module.s3.cloudtrail_bucket_id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  sns_topic_name                = aws_sns_topic.security_alerts.arn != "" ? aws_sns_topic.security_alerts.arn : null

  depends_on = [module.s3]

  tags = {
    Name        = "capsa-cloudtrail"
    Environment = var.environment
  }
}

# ── ECS (ClamAV + Redis + Queue Worker) ──────────────────────────────────

module "ecs" {
  source = "./modules/ecs"

  environment                    = var.environment
  ecs_names                      = module.naming.ecs
  log_group_names                = module.naming.cloudwatch_log
  subnet_ids                     = module.networking.subnet_ids
  clamav_service_sg_id           = module.networking.clamav_service_sg_id
  redis_sg_id                    = module.networking.redis_sg_id
  ecs_task_execution_role_arn    = module.iam.ecs_task_execution_role_arn
  ecs_task_role_arn              = module.iam.ecs_task_role_arn
  clamav_image                   = var.clamav_image
  clamav_port                    = var.clamav_port
  clamav_cpu                     = var.clamav_cpu
  clamav_memory                  = var.clamav_memory
  ecs_assign_public_ip           = var.ecs_assign_public_ip
  service_discovery_namespace_id = module.networking.service_discovery_namespace_id
  service_discovery_redis_id     = module.networking.service_discovery_redis_id
  redis_dns_name                 = module.networking.redis_dns_name
  service_discovery_clamav_id    = module.networking.service_discovery_clamav_id
  clamav_dns_name                = module.networking.clamav_dns_name
  aws_region                     = var.aws_region
  routing_function_name          = module.lambda.routing_engine_function_name
}

# ── Monitoring (Alarms, EventBridge) ─────────────────────────────────────

module "monitoring" {
  source = "./modules/monitoring"

  environment                    = var.environment
  sns_topic_arn                  = aws_sns_topic.security_alerts.arn
  lambda_function_names          = module.naming.lambda_function
  report_generator_function_arn  = module.lambda.report_generator_function_arn
  report_generator_function_name = module.lambda.report_generator_function_name
  report_schedule_daily          = var.report_schedule_daily
  report_schedule_weekly         = var.report_schedule_weekly
}
