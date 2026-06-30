output "prefix" {
  value       = local.prefix
  description = "Resource name prefix: {app}-{env}"
}

output "s3_bucket" {
  value       = local.s3_bucket
  description = "Map of S3 bucket names by zone"
}

output "lambda_function" {
  value       = local.lambda_function
  description = "Map of Lambda function names"
}

output "iam_role" {
  value       = local.iam_role
  description = "Map of IAM role names"
}

output "ecs" {
  value       = local.ecs
  description = "Map of ECS resource names"
}

output "sns_topic" {
  value       = local.sns_topic
  description = "SNS topic name"
}

output "kms_alias" {
  value       = local.kms_alias
  description = "Map of KMS key aliases by zone"
}

output "cloudwatch_log" {
  value       = local.cloudwatch_log
  description = "Map of CloudWatch log group names"
}

output "service_discovery_namespace" {
  value       = local.service_discovery_namespace
  description = "Service discovery namespace name"
}

output "service_discovery_service" {
  value       = local.service_discovery_service
  description = "Service discovery service name"
}
