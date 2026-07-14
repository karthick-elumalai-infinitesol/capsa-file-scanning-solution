# CAPSA — OpenSecOps Analyzer
# Copy infrastructure/terraform.tfvars.example to terraform.tfvars for actual values

aws_region  = "us-east-2"
environment = "prod"

# Jira Cloud Configuration
jira_url         = "https://placeholder.atlassian.net"
jira_username    = "placeholder@example.com"
jira_api_token   = "placeholder-token"
jira_project_key = "SEC"

# Alerting
alert_email       = "test-alerts@example.com"
slack_webhook_url = ""

# ClamAV ECS Fargate
clamav_image  = "203733861310.dkr.ecr.us-east-2.amazonaws.com/capsa/clamav:1.5.2-debian13-slim-amd64"
clamav_port   = 3310
clamav_cpu    = 1024
clamav_memory = 2048

# Lambda
lambda_timeout = 300
lambda_memory  = 1024

# VPC — set these to your existing VPC resources
vpc_id               = ""
subnet_ids           = []
route_table_ids      = []
security_group_ids   = []
ecs_assign_public_ip = true

# GuardDuty
guardduty_findings_lookback_minutes = 60

# Report schedules (UTC)
report_schedule_daily  = "cron(0 1 * * ? *)"
report_schedule_weekly = "cron(0 2 ? * SUN *)"

# Redis URL (for scan_trigger Lambda → ECS Redis)
redis_url = "redis://redis.capsa.internal:6379/0"

# SFTPGo
sftpgo_admin_password = "change-me-in-production"
