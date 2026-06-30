variable "environment" {
  description = "Environment name for tagging"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for deployment. Empty string uses default VPC."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for Lambda and ECS. Empty list uses default subnets."
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Additional security group IDs to attach"
  type        = list(string)
  default     = []
}

variable "route_table_ids" {
  description = "Route table IDs for private subnets that need the S3 Gateway VPC endpoint"
  type        = list(string)
  default     = []
}

variable "service_discovery_namespace" {
  description = "Name for the private DNS namespace"
  type        = string
  default     = "capsa.internal"
}

variable "clamav_port" {
  description = "ClamAV TCP port"
  type        = number
  default     = 3310
}
