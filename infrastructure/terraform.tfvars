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
clamav_image  = "clamav/clamav:1.5.2-debian13-slim"
clamav_port   = 3310
clamav_cpu    = 1024
clamav_memory = 2048

# Lambda
lambda_timeout = 300
lambda_memory  = 1024

# VPC — existing capsa-security-vpc
vpc_id               = "vpc-0fda7741240060f98"
subnet_ids           = ["subnet-0cdeee2d292b721c5", "subnet-0bc5e6308b3c73cb0"]
route_table_ids      = ["rtb-097779093cff3b9fd", "rtb-0224cc2425a1ed005"]
security_group_ids   = []
ecs_assign_public_ip = false

guardduty_findings_lookback_minutes = 60

report_schedule_daily  = "cron(0 1 * * ? *)"
report_schedule_weekly = "cron(0 2 ? * SUN *)"

redis_url = "redis://redis.capsa.internal:6379/0"
