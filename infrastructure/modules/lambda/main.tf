# ============================================================================
# LAMBDA: File Routing Engine
# Routes files based on scan results (clean → clean bucket, infected → quarantine)
# ============================================================================

data "archive_file" "routing_engine" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda_functions/routing_engine"
  output_path = "${path.module}/routing_engine.zip"
}

resource "aws_lambda_function" "routing_engine" {
  filename         = data.archive_file.routing_engine.output_path
  function_name    = var.function_names["routing"]
  role             = var.scan_engine_role_arn
  handler          = "index.lambda_handler"
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  source_code_hash = data.archive_file.routing_engine.output_base64sha256

  environment {
    variables = {
      STAGING_BUCKET    = var.staging_bucket_id
      CLEAN_BUCKET      = var.clean_bucket_id
      QUARANTINE_BUCKET = var.quarantine_bucket_id
      SNS_TOPIC_ARN     = var.sns_topic_arn
      JIRA_URL          = var.jira_url
      JIRA_USERNAME     = var.jira_username
      JIRA_PROJECT_KEY  = var.jira_project_key
      CLAMAV_ENABLED    = "true"
      LOG_LEVEL         = "INFO"
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
    Name        = var.function_names["routing"]
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "routing_engine" {
  name              = var.log_group_names["routing"]
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["routing"]
    Environment = var.environment
  }
}

# Lambda permission for scan_trigger to invoke routing engine
resource "aws_lambda_permission" "scan_trigger_invoke_routing" {
  statement_id  = "AllowScanTriggerInvokeRouting"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.routing_engine.function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = aws_lambda_function.scan_trigger.arn
}

# ============================================================================
# LAMBDA: Report Generator
# Generates daily/weekly reports via EventBridge schedule
# ============================================================================

data "archive_file" "report_generator" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda_functions/report_generator"
  output_path = "${path.module}/report_generator.zip"
}

resource "aws_lambda_function" "report_generator" {
  filename         = data.archive_file.report_generator.output_path
  function_name    = var.function_names["report_gen"]
  role             = var.report_generator_role_arn
  handler          = "index.lambda_handler"
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  source_code_hash = data.archive_file.report_generator.output_base64sha256

  environment {
    variables = {
      STAGING_BUCKET    = var.staging_bucket_id
      CLEAN_BUCKET      = var.clean_bucket_id
      QUARANTINE_BUCKET = var.quarantine_bucket_id
      REPORTS_BUCKET    = var.reports_bucket_id
      SNS_TOPIC_ARN     = var.sns_topic_arn
      LOG_LEVEL         = "INFO"
    }
  }

  tags = {
    Name        = var.function_names["report_gen"]
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "report_generator" {
  name              = "/aws/lambda/${var.function_names["report_gen"]}"
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["report_gen"]
    Environment = var.environment
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "scan_trigger_function_name" {
  value       = aws_lambda_function.scan_trigger.function_name
  description = "Name of scan_trigger Lambda"
}

output "scan_trigger_function_arn" {
  value       = aws_lambda_function.scan_trigger.arn
  description = "ARN of scan_trigger Lambda"
}

output "routing_engine_function_name" {
  value       = aws_lambda_function.routing_engine.function_name
  description = "Name of routing engine Lambda"
}

output "routing_engine_function_arn" {
  value       = aws_lambda_function.routing_engine.arn
  description = "ARN of routing engine Lambda"
}

output "report_generator_function_name" {
  value       = aws_lambda_function.report_generator.function_name
  description = "Name of report generator Lambda"
}

output "report_generator_function_arn" {
  value       = aws_lambda_function.report_generator.arn
  description = "ARN of report generator Lambda"
}
