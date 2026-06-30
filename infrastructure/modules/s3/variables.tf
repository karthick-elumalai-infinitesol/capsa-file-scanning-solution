variable "environment" {
  description = "Environment name for tagging"
  type        = string
}

variable "bucket_names" {
  description = "Map of S3 bucket names by zone (staging, clean, quarantine, reports, logging, cloudtrail)"
  type        = map(string)
}

variable "staging_key_arn" {
  description = "ARN of KMS key for staging bucket"
  type        = string
}

variable "clean_key_arn" {
  description = "ARN of KMS key for clean bucket"
  type        = string
  default     = ""
}

variable "quarantine_key_arn" {
  description = "ARN of KMS key for quarantine bucket"
  type        = string
}
