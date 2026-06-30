variable "environment" {
  description = "Environment name"
  type        = string
}

variable "function_names" {
  description = "Map of Lambda function names"
  type        = map(string)
}

variable "log_group_names" {
  description = "Map of CloudWatch log group names"
  type        = map(string)
}

variable "scan_trigger_role_arn" {
  description = "ARN of scan_trigger Lambda execution role"
  type        = string
}

variable "scan_engine_role_arn" {
  description = "ARN of scan engine Lambda execution role"
  type        = string
}

variable "report_generator_role_arn" {
  description = "ARN of report generator Lambda execution role"
  type        = string
}

variable "staging_bucket_id" {
  description = "Staging S3 bucket name"
  type        = string
}

variable "clean_bucket_id" {
  description = "Clean S3 bucket name"
  type        = string
}

variable "quarantine_bucket_id" {
  description = "Quarantine S3 bucket name"
  type        = string
}

variable "reports_bucket_id" {
  description = "Reports S3 bucket name"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of SNS security alerts topic"
  type        = string
}

variable "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  type        = string
  default     = ""
}

variable "guardduty_lookback_minutes" {
  description = "GuardDuty findings lookback window in minutes"
  type        = number
  default     = 60
}

variable "routing_lambda_name" {
  description = "Name of routing engine Lambda"
  type        = string
}

variable "jira_url" {
  description = "Jira instance URL"
  type        = string
  default     = ""
}

variable "jira_username" {
  description = "Jira username/email"
  type        = string
  default     = ""
}

variable "jira_project_key" {
  description = "Jira project key"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for VPC Lambda (empty = no VPC)"
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Security group IDs for VPC Lambda"
  type        = list(string)
  default     = []
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda memory in MB"
  type        = number
  default     = 1024
}

variable "redis_url" {
  description = "Redis URL for scan_trigger to enqueue scan jobs"
  type        = string
  default     = "redis://redis.capsa.internal:6379/0"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}
