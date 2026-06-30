# ============================================================================
# Monitoring — CloudWatch Alarms + EventBridge Rules
# SNS topic is created in root module and passed in to avoid circular deps.
# ============================================================================

# ── EventBridge Rules for Scheduled Reports ───────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_report" {
  name                = "capsa-daily-report"
  description         = "Triggers daily CAPSA scan report"
  schedule_expression = var.report_schedule_daily
  tags = {
    Name        = "capsa-daily-report"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_rule" "weekly_report" {
  name                = "capsa-weekly-report"
  description         = "Triggers weekly CAPSA scan report"
  schedule_expression = var.report_schedule_weekly
  tags = {
    Name        = "capsa-weekly-report"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "daily_report_lambda" {
  rule  = aws_cloudwatch_event_rule.daily_report.name
  arn   = var.report_generator_function_arn
  input = jsonencode({ report_type = "daily" })
}

resource "aws_cloudwatch_event_target" "weekly_report_lambda" {
  rule  = aws_cloudwatch_event_rule.weekly_report.name
  arn   = var.report_generator_function_arn
  input = jsonencode({ report_type = "weekly" })
}

resource "aws_lambda_permission" "allow_eventbridge_daily" {
  statement_id  = "AllowEventBridgeDailyReport"
  action        = "lambda:InvokeFunction"
  function_name = var.report_generator_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_report.arn
}

resource "aws_lambda_permission" "allow_eventbridge_weekly" {
  statement_id  = "AllowEventBridgeWeeklyReport"
  action        = "lambda:InvokeFunction"
  function_name = var.report_generator_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_report.arn
}

# ── CloudWatch Alarms ─────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "scan_trigger_errors" {
  alarm_name          = "capsa-scan-trigger-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"

  dimensions = {
    FunctionName = var.lambda_function_names["scan_trigger"]
  }

  alarm_actions = [var.sns_topic_arn]

  tags = {
    Name        = "capsa-scan-trigger-errors"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "routing_engine_errors" {
  alarm_name          = "capsa-routing-engine-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"

  dimensions = {
    FunctionName = var.lambda_function_names["routing"]
  }

  alarm_actions = [var.sns_topic_arn]

  tags = {
    Name        = "capsa-routing-engine-errors"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "scan_trigger_duration" {
  alarm_name          = "capsa-scan-trigger-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "60000"

  dimensions = {
    FunctionName = var.lambda_function_names["scan_trigger"]
  }

  alarm_actions = [var.sns_topic_arn]

  tags = {
    Name        = "capsa-scan-trigger-duration"
    Environment = var.environment
  }
}
