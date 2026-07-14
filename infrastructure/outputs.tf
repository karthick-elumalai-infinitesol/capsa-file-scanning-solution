output "staging_bucket" {
  value       = module.s3.staging_bucket_id
  description = "Staging S3 bucket name"
}

output "clean_bucket" {
  value       = module.s3.clean_bucket_id
  description = "Clean S3 bucket name"
}

output "quarantine_bucket" {
  value       = module.s3.quarantine_bucket_id
  description = "Quarantine S3 bucket name"
}

output "reports_bucket" {
  value       = module.s3.reports_bucket_id
  description = "Reports S3 bucket name"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS topic ARN for security alerts"
}

output "guardduty_detector_id" {
  value       = module.security.guardduty_detector_id
  description = "GuardDuty detector ID"
}

output "scan_trigger_function_name" {
  value       = module.lambda.scan_trigger_function_name
  description = "Name of scan_trigger Lambda function"
}

output "routing_engine_function_name" {
  value       = module.lambda.routing_engine_function_name
  description = "Name of routing engine Lambda function"
}

output "report_generator_function_name" {
  value       = module.lambda.report_generator_function_name
  description = "Name of report generator Lambda function"
}

output "ecs_cluster_name" {
  value       = module.ecs.cluster_name
  description = "ECS cluster name"
}

output "clamav_dns_name" {
  value       = module.networking.clamav_dns_name
  description = "DNS name for ClamAV service discovery"
}

output "sftpgo_dns_name" {
  value       = module.networking.sftpgo_dns_name
  description = "DNS name for SFTPGo service discovery"
}

output "sftpgo_security_group_id" {
  value       = module.networking.sftpgo_service_sg_id
  description = "Security group ID for SFTPGo"
}

output "sftpgo_task_definition_arn" {
  value       = module.ecs.sftpgo_task_definition_arn
  description = "SFTPGo ECS task definition ARN"
}

output "sftpgo_admin_secret_arn" {
  value       = module.security.sftpgo_admin_secret_arn
  description = "ARN of SFTPGo admin password in Secrets Manager"
}
