# ============================================================================
# LAMBDA: File Scan Trigger
# Triggered by S3 ObjectCreated. Enqueues scan jobs to Redis in ECS.
# ============================================================================

data "archive_file" "scan_trigger_code" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda_functions/scan_trigger"
  output_path = "${path.module}/scan_trigger_code.zip"
}

# Build Lambda layer with redis-py dependency
resource "null_resource" "redis_layer_build" {
  triggers = {
    requirements = filesha1("${path.module}/../../../lambda_functions/scan_trigger/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${path.module}/redis_layer/python && \
      python3 -m pip install --quiet --no-cache-dir \
        -r ${path.module}/../../../lambda_functions/scan_trigger/requirements.txt \
        --target ${path.module}/redis_layer/python
    EOT
  }
}

data "archive_file" "redis_layer" {
  type        = "zip"
  output_path = "${path.module}/redis_layer.zip"
  source_dir  = "${path.module}/redis_layer"
  depends_on  = [null_resource.redis_layer_build]
}

resource "aws_lambda_layer_version" "redis" {
  filename            = data.archive_file.redis_layer.output_path
  layer_name          = "capsa-redis"
  source_code_hash    = data.archive_file.redis_layer.output_base64sha256
  compatible_runtimes = ["python3.11"]
  description         = "Redis-py client library for CAPSA scan_trigger Lambda"
}

resource "aws_lambda_function" "scan_trigger" {
  filename         = data.archive_file.scan_trigger_code.output_path
  function_name    = var.function_names["scan_trigger"]
  role             = var.scan_trigger_role_arn
  handler          = "index.lambda_handler"
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  source_code_hash = data.archive_file.scan_trigger_code.output_base64sha256
  layers           = [aws_lambda_layer_version.redis.arn]

  environment {
    variables = {
      STAGING_BUCKET             = var.staging_bucket_id
      QUARANTINE_BUCKET          = var.quarantine_bucket_id
      SNS_TOPIC_ARN              = var.sns_topic_arn
      ROUTING_LAMBDA_NAME        = var.routing_lambda_name
      GUARDDUTY_DETECTOR_ID      = var.guardduty_detector_id
      GUARDDUTY_LOOKBACK_MINUTES = tostring(var.guardduty_lookback_minutes)
      JIRA_URL                   = var.jira_url
      JIRA_USERNAME              = var.jira_username
      JIRA_PROJECT_KEY           = var.jira_project_key
      REDIS_URL                  = var.redis_url
      QUEUE_BACKEND              = "redis"
      LOG_LEVEL                  = "INFO"
    }
  }

  dynamic "vpc_config" {
    for_each = length(var.subnet_ids) > 0 ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  tags = {
    Name        = var.function_names["scan_trigger"]
    Environment = var.environment
  }
}
