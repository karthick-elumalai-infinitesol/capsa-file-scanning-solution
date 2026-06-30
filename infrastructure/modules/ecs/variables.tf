variable "environment" {
  description = "Environment name for tagging"
  type        = string
}

variable "ecs_names" {
  description = "Map of ECS resource names from naming module"
  type        = map(string)
}

variable "log_group_names" {
  description = "Map of CloudWatch log group names"
  type        = map(string)
}

variable "subnet_ids" {
  description = "List of subnet IDs for ECS tasks"
  type        = list(string)
}

variable "clamav_service_sg_id" {
  description = "Security group ID for ClamAV service"
  type        = string
}

variable "redis_sg_id" {
  description = "Security group ID for Redis service"
  type        = string
}

variable "ecs_task_execution_role_arn" {
  description = "ARN of ECS task execution role"
  type        = string
}

variable "ecs_task_role_arn" {
  description = "ARN of ECS task role"
  type        = string
}

variable "clamav_image" {
  description = "ClamAV Docker image"
  type        = string
  default     = "clamav/clamav:1.5.2-debian13-slim"
}

variable "scanner_image" {
  description = "CAPSA scanner Docker image"
  type        = string
  default     = "203733861310.dkr.ecr.us-east-2.amazonaws.com/capsa-scanner:enterprise"
}

variable "redis_image" {
  description = "Redis Docker image"
  type        = string
  default     = "redis:7-alpine"
}

variable "clamav_port" {
  description = "ClamAV TCP port"
  type        = number
  default     = 3310
}

variable "clamav_cpu" {
  description = "ClamAV CPU units"
  type        = number
  default     = 1024
}

variable "clamav_memory" {
  description = "ClamAV memory MB"
  type        = number
  default     = 2048
}

variable "worker_cpu" {
  description = "Queue worker CPU units"
  type        = number
  default     = 512
}

variable "worker_memory" {
  description = "Queue worker memory MB"
  type        = number
  default     = 1024
}

variable "redis_cpu" {
  description = "Redis CPU units"
  type        = number
  default     = 256
}

variable "redis_memory" {
  description = "Redis memory MB"
  type        = number
  default     = 512
}

variable "ecs_assign_public_ip" {
  description = "Assign public IP to ECS tasks"
  type        = bool
  default     = true
}

variable "service_discovery_namespace_id" {
  description = "Service discovery namespace ID"
  type        = string
  default     = ""
}

variable "service_discovery_redis_id" {
  description = "Service discovery service ID for Redis"
  type        = string
  default     = ""
}

variable "redis_dns_name" {
  description = "DNS name for Redis"
  type        = string
  default     = "redis.capsa.internal"
}

variable "service_discovery_clamav_id" {
  description = "Service discovery service ID for ClamAV"
  type        = string
  default     = ""
}

variable "clamav_dns_name" {
  description = "DNS name for ClamAV"
  type        = string
  default     = "clamav.capsa.internal"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "routing_function_name" {
  description = "Routing engine Lambda function name"
  type        = string
}
