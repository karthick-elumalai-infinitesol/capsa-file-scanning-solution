output "staging_bucket_id" {
  value       = aws_s3_bucket.staging.id
  description = "Staging S3 bucket name/ID"
}

output "staging_bucket_arn" {
  value       = aws_s3_bucket.staging.arn
  description = "Staging S3 bucket ARN"
}

output "clean_bucket_id" {
  value       = aws_s3_bucket.clean.id
  description = "Clean S3 bucket name/ID"
}

output "clean_bucket_arn" {
  value       = aws_s3_bucket.clean.arn
  description = "Clean S3 bucket ARN"
}

output "quarantine_bucket_id" {
  value       = aws_s3_bucket.quarantine.id
  description = "Quarantine S3 bucket name/ID"
}

output "quarantine_bucket_arn" {
  value       = aws_s3_bucket.quarantine.arn
  description = "Quarantine S3 bucket ARN"
}

output "reports_bucket_id" {
  value       = aws_s3_bucket.reports.id
  description = "Reports S3 bucket name/ID"
}

output "reports_bucket_arn" {
  value       = aws_s3_bucket.reports.arn
  description = "Reports S3 bucket ARN"
}

output "logging_bucket_id" {
  value       = aws_s3_bucket.logging.id
  description = "Logging S3 bucket name/ID"
}

output "cloudtrail_bucket_id" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "CloudTrail S3 bucket name/ID"
}


