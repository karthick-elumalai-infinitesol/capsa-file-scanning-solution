output "staging_key_arn" {
  value       = aws_kms_key.staging.arn
  description = "ARN of staging KMS key"
}

output "staging_key_id" {
  value       = aws_kms_key.staging.key_id
  description = "ID of staging KMS key"
}

output "clean_key_arn" {
  value       = aws_kms_key.clean.arn
  description = "ARN of clean KMS key"
}

output "clean_key_id" {
  value       = aws_kms_key.clean.key_id
  description = "ID of clean KMS key"
}

output "quarantine_key_arn" {
  value       = aws_kms_key.quarantine.arn
  description = "ARN of quarantine KMS key"
}

output "quarantine_key_id" {
  value       = aws_kms_key.quarantine.key_id
  description = "ID of quarantine KMS key"
}

output "sftpgo_admin_secret_arn" {
  value       = aws_secretsmanager_secret.sftpgo_admin.arn
  description = "ARN of SFTPGo admin password secret"
}

output "guardduty_detector_id" {
  value       = try(aws_guardduty_detector.main[0].id, "")
  description = "GuardDuty detector ID"
}
