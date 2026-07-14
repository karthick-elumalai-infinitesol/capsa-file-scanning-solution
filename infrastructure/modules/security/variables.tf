variable "environment" {
  description = "Environment name for tagging"
  type        = string
}

variable "bucket_names" {
  description = "Map of S3 bucket names by zone"
  type        = map(string)
}

variable "kms_alias_names" {
  description = "Map of KMS key aliases by zone"
  type        = map(string)
}

variable "sns_topic_arn" {
  description = "ARN of SNS security alerts topic"
  type        = string
  default     = ""
}

variable "guardduty_enable" {
  description = "Enable GuardDuty detector"
  type        = bool
  default     = true
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "sftpgo_admin_password" {
  description = "SFTPGo admin password (stored in Secrets Manager)"
  type        = string
  sensitive   = true
}
