output "scan_trigger_role_arn" {
  value       = aws_iam_role.scan_trigger.arn
  description = "ARN of scan_trigger Lambda execution role"
}

output "scan_trigger_role_name" {
  value       = aws_iam_role.scan_trigger.name
  description = "Name of scan_trigger Lambda execution role"
}

output "scan_engine_role_arn" {
  value       = aws_iam_role.scan_engine.arn
  description = "ARN of scan engine (routing) Lambda execution role"
}

output "scan_engine_role_name" {
  value       = aws_iam_role.scan_engine.name
  description = "Name of scan engine Lambda execution role"
}

output "report_generator_role_arn" {
  value       = aws_iam_role.report_generator.arn
  description = "ARN of report generator Lambda execution role"
}

output "report_generator_role_name" {
  value       = aws_iam_role.report_generator.name
  description = "Name of report generator Lambda execution role"
}

output "ecs_task_execution_role_arn" {
  value       = aws_iam_role.ecs_task_execution.arn
  description = "ARN of ECS task execution role"
}

output "ecs_task_execution_role_name" {
  value       = aws_iam_role.ecs_task_execution.name
  description = "Name of ECS task execution role"
}

output "ecs_task_role_arn" {
  value       = aws_iam_role.ecs_task.arn
  description = "ARN of ECS task role"
}

output "ecs_task_role_name" {
  value       = aws_iam_role.ecs_task.name
  description = "Name of ECS task role"
}

output "migration_team_role_arn" {
  value       = aws_iam_role.migration_team.arn
  description = "ARN of migration team IAM role"
}

output "security_team_role_arn" {
  value       = aws_iam_role.security_team.arn
  description = "ARN of security team read-only IAM role"
}
