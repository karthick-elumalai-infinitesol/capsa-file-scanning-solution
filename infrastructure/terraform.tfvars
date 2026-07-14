aws_region  = "us-east-2"
environment = "prod"

# Jira — placeholder for initial test deployment
jira_url         = "https://placeholder.atlassian.net"
jira_username    = "placeholder@example.com"
jira_api_token   = "placeholder-token"
jira_project_key = "SEC"

# Alerting — placeholder email for test
alert_email       = "test-alerts@example.com"
slack_webhook_url = ""

# ClamAV
clamav_image  = "203733861310.dkr.ecr.us-east-2.amazonaws.com/capsa/clamav:1.5.2-debian13-slim-amd64"
clamav_port   = 3310
clamav_cpu    = 1024
clamav_memory = 2048

# Lambda
lambda_timeout = 300
lambda_memory  = 1024

# VPC — existing capsa-security-vpc (re-created after previous teardown)
vpc_id               = "vpc-0421590b00e97127a"
subnet_ids           = ["subnet-0e7e7b4f01db3ca77", "subnet-08201b5e213326957"]
route_table_ids      = ["rtb-0cd58f34714252e9a", "rtb-0743a2d6c36845d7e", "rtb-0b40032f867e67d8c"]
security_group_ids   = []
ecs_assign_public_ip = true

guardduty_findings_lookback_minutes = 60

report_schedule_daily  = "cron(0 1 * * ? *)"
report_schedule_weekly = "cron(0 2 ? * SUN *)"

redis_url = "redis://redis.capsa.internal:6379/0"

sftpgo_admin_password = "change-me-in-production"
