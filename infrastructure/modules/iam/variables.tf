variable "environment" {
  description = "Environment name for tagging"
  type        = string
}

variable "role_names" {
  description = "Map of IAM role names"
  type        = map(string)
}

variable "function_names" {
  description = "Map of Lambda function names (for cross-account permissions)"
  type        = map(string)
}

variable "staging_bucket_arn" {
  description = "ARN of staging S3 bucket"
  type        = string
}

variable "clean_bucket_arn" {
  description = "ARN of clean S3 bucket"
  type        = string
}

variable "quarantine_bucket_arn" {
  description = "ARN of quarantine S3 bucket"
  type        = string
}

variable "reports_bucket_arn" {
  description = "ARN of reports S3 bucket"
  type        = string
}

variable "staging_key_arn" {
  description = "ARN of staging KMS key"
  type        = string
}

variable "clean_key_arn" {
  description = "ARN of clean/prod KMS key"
  type        = string
  default     = ""
}

variable "quarantine_key_arn" {
  description = "ARN of quarantine KMS key"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of SNS security alerts topic"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "enable_vpc" {
  description = "Whether VPC networking is enabled"
  type        = bool
  default     = false
}
