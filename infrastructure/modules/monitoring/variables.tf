variable "environment" {
  description = "Environment name"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of SNS topic for alarms"
  type        = string
}

variable "lambda_function_names" {
  description = "Map of Lambda function names"
  type        = map(string)
}

variable "report_generator_function_arn" {
  description = "ARN of report generator Lambda"
  type        = string
}

variable "report_generator_function_name" {
  description = "Name of report generator Lambda"
  type        = string
}

variable "report_schedule_daily" {
  description = "Cron expression for daily report"
  type        = string
  default     = "cron(0 1 * * ? *)"
}

variable "report_schedule_weekly" {
  description = "Cron expression for weekly report"
  type        = string
  default     = "cron(0 2 ? * SUN *)"
}
