output "sns_topic_arn" {
  value       = var.sns_topic_arn
  description = "ARN of security alerts SNS topic"
}

output "sns_topic_name" {
  value       = try(reverse(split("/", var.sns_topic_arn))[0], "capsa-security-alerts")
  description = "Name of security alerts SNS topic"
}
