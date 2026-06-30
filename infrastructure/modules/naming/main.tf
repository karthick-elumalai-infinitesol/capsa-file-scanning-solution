locals {
  prefix = "${var.application}-${var.environment}"

  s3_bucket = {
    staging    = "capsa-staging-${var.account_id}"
    clean      = "capsa-clean-${var.account_id}"
    quarantine = "capsa-quarantine-${var.account_id}"
    reports    = "capsa-reports-${var.account_id}"
    logging    = "capsa-logging-${var.account_id}"
    cloudtrail = "capsa-cloudtrail-${var.account_id}"
  }

  lambda_function = {
    scan_trigger = "${local.prefix}-file-scan-trigger"
    routing      = "${local.prefix}-file-routing-engine"
    report_gen   = "${local.prefix}-report-generator"
  }

  iam_role = {
    scan_trigger     = "${local.prefix}-lambda-scan-trigger-role"
    scan_engine      = "${local.prefix}-lambda-scan-engine-role"
    report_generator = "${local.prefix}-lambda-report-generator-role"
    ecs_execution    = "${local.prefix}-ecs-task-execution-role"
    ecs_task         = "${local.prefix}-ecs-task-role"
  }

  ecs = {
    cluster          = "${local.prefix}-clamav-cluster"
    service_clamav   = "${local.prefix}-clamav-service"
    service_worker   = "${local.prefix}-queue-worker-service"
    service_redis    = "${local.prefix}-redis-service"
    task_clamav      = "${local.prefix}-clamav-task"
    task_worker      = "${local.prefix}-queue-worker-task"
    task_redis       = "${local.prefix}-redis-task"
    log_group_clamav = "/ecs/${local.prefix}-clamav"
    log_group_worker = "/ecs/${local.prefix}-queue-worker"
    log_group_redis  = "/ecs/${local.prefix}-redis"
  }

  sns_topic = "${local.prefix}-security-alerts"
  kms_alias = {
    staging    = "alias/${local.prefix}-staging-key"
    clean      = "alias/${local.prefix}-clean-key"
    quarantine = "alias/${local.prefix}-quarantine-key"
  }
  cloudwatch_log = {
    scan_trigger = "/aws/lambda/${local.prefix}-file-scan-trigger"
    routing      = "/aws/lambda/${local.prefix}-file-routing-engine"
    report_gen   = "/aws/lambda/${local.prefix}-report-generator"
    clamav       = "/ecs/${local.prefix}-clamav"
    worker       = "/ecs/${local.prefix}-queue-worker"
    redis        = "/ecs/${local.prefix}-redis"
  }
  service_discovery_namespace = "${var.application}.internal"
  service_discovery_service   = "${var.application}-clamav"
}
