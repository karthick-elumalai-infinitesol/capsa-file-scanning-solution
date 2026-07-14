variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "jira_url" {
  description = "Jira Cloud instance URL"
  type        = string
  sensitive   = true
}

variable "jira_username" {
  description = "Jira username (email)"
  type        = string
  sensitive   = true
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  sensitive   = true
}

variable "jira_project_key" {
  description = "Jira project key"
  type        = string
  default     = "SEC"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "clamav_image" {
  description = "ClamAV Docker image tag"
  type        = string
  default     = "clamav/clamav:1.5.2-debian13-slim"
}

variable "clamav_port" {
  description = "ClamAV daemon port"
  type        = number
  default     = 3310
}

variable "clamav_cpu" {
  description = "CPU units for ClamAV ECS task"
  type        = number
  default     = 1024
}

variable "clamav_memory" {
  description = "Memory MB for ClamAV ECS task"
  type        = number
  default     = 2048
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 1024
}

variable "subnet_ids" {
  description = "List of VPC subnet IDs for Lambda and ECS (leave empty for default VPC)"
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Additional security group IDs for Lambda"
  type        = list(string)
  default     = []
}

variable "route_table_ids" {
  description = "Route table IDs for private subnets that need the S3 Gateway VPC endpoint"
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "VPC ID (leave empty for default VPC)"
  type        = string
  default     = ""
}

variable "ecs_assign_public_ip" {
  description = "Assign public IP to ECS tasks"
  type        = bool
  default     = true
}

variable "guardduty_findings_lookback_minutes" {
  description = "Lookback window in minutes for GuardDuty findings"
  type        = number
  default     = 60
}

variable "report_schedule_daily" {
  description = "Cron expression for daily report trigger"
  type        = string
  default     = "cron(0 1 * * ? *)"
}

variable "report_schedule_weekly" {
  description = "Cron expression for weekly report trigger"
  type        = string
  default     = "cron(0 2 ? * SUN *)"
}

variable "cloudtrail_enable" {
  description = "Enable CloudTrail trail"
  type        = bool
  default     = true
}

variable "redis_url" {
  description = "Redis URL for scan_trigger to enqueue scan jobs"
  type        = string
  default     = "redis://redis.capsa.internal:6379/0"
}

variable "sftpgo_admin_password" {
  description = "SFTPGo admin password (stored in Secrets Manager)"
  type        = string
  sensitive   = true
}
