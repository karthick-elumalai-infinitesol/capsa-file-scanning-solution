variable "application" {
  description = "Application name abbreviation (e.g. capsa)"
  type        = string
  default     = "capsa"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "account_id" {
  description = "AWS account ID for unique naming"
  type        = string
}
