# CAPSA Healthcare - Infrastructure as Code

Complete Terraform configuration to deploy the 3-zone AWS infrastructure for OpenSecOps-Analyzer healthcare file scanning system.

## Architecture

### 3-Zone Design

```
Zone 1: STAGING       Zone 2: SCANNING        Zone 3: OUTCOME
┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ S3 Staging      │   │ AWS Lambda       │   │ S3 Clean Bucket  │
│ (Inbound)       │──→│ • File Scan      │──→│ (Production)     │
│                 │   │ • GuardDuty      │   │                  │
│ VPC Endpoint    │   │ • ClamAV         │   │ S3 Quarantine    │
│ KMS Encrypted   │   │                  │   │ (WORM)           │
└─────────────────┘   │ SNS Alerts       │   │ Object Lock      │
                      │ Jira Tickets     │   │ 7-year Retention │
                      └──────────────────┘   └──────────────────┘
```

## Components

### 1. S3 Buckets
- **capsa-staging-intake**: Inbound file staging (30-day retention, auto-delete)
- **capsa-prod-data**: Production clean files (versioning enabled)
- **capsa-quarantine**: Infected files (Object Lock COMPLIANCE, 7-year retention)
- **capsa-logs**: Centralized access logging
- **capsa-cloudtrail**: CloudTrail audit logs (7-year HIPAA compliance)

### 2. Encryption
- KMS keys for each zone (staging, production, quarantine)
- TLS 1.2+ enforced for all data in transit
- Server-side encryption with KMS for all buckets

### 3. Lambda Functions
- **capsa-file-scan-trigger**: Triggered by S3 events, orchestrates scanning
- **capsa-file-routing-engine**: Routes files based on scan results

### 4. Monitoring & Alerting
- SNS topic for security alerts (Email, Slack, PagerDuty)
- CloudWatch logs for Lambda functions
- CloudWatch alarms for errors and performance

### 5. Compliance
- CloudTrail for audit logging (7-year retention)
- VPC endpoints (optional) for private S3 access
- Object Lock COMPLIANCE mode for quarantine immutability
- Access controls via IAM roles

## Prerequisites

### Required Software
```bash
# Terraform (>= 1.0)
# See: https://www.terraform.io/downloads.html

# AWS CLI v2
# See: https://aws.amazon.com/cli/

# jq (optional, for parsing JSON output)
# brew install jq  # macOS
# apt-get install jq  # Ubuntu/Debian
```

### AWS Account Setup
```bash
# Configure AWS credentials
aws configure

# Verify access
aws sts get-caller-identity
```

### Required AWS Permissions
Your IAM user/role must have permissions to:
- Create/manage S3 buckets
- Create/manage KMS keys
- Create/manage Lambda functions
- Create/manage IAM roles
- Create/manage SNS topics
- Create/manage CloudWatch logs
- Create/manage CloudTrail

## Deployment Steps

### 1. Copy Configuration Template
```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
```

### 2. Edit terraform.tfvars
Update with your values:
```bash
# Edit terraform.tfvars
vim terraform.tfvars
```

**Required values:**
- `jira_url`: Your Jira Cloud instance URL
- `jira_api_token`: Jira API token (from Settings → Security → API tokens)
- `jira_project_key`: Jira project key (e.g., "SEC")
- `virustotal_api_key`: VirusTotal API key (optional)
- `alert_email`: Email for SNS notifications

### 3. Plan Deployment
```bash
./scripts/deploy.sh prod plan
```

Review the Terraform plan output to verify all resources.

### 4. Apply Infrastructure
```bash
./scripts/deploy.sh prod apply
```

This will:
- Create all S3 buckets with encryption
- Set up KMS keys
- Deploy Lambda functions
- Configure SNS alerts
- Enable CloudTrail
- Create IAM roles and policies

**Duration:** 5-10 minutes

### 5. Verify Deployment
```bash
# Get outputs
./scripts/deploy.sh prod output

# Or
terraform output
```

## Post-Deployment

### 1. Confirm SNS Email Subscription
Check your email for SNS subscription confirmation and click "Confirm subscription".

### 2. Upload Test Data
```bash
# Generate 1TB of test data (malware + clean samples)
python scripts/generate_test_data.py \
  --bucket capsa-staging-intake-YOUR_ACCOUNT_ID \
  --size 1.0 \
  --prefix test-data

# Or generate smaller dataset for quick testing
python scripts/generate_test_data.py \
  --bucket capsa-staging-intake-YOUR_ACCOUNT_ID \
  --size 0.01 \
  --prefix test-data
```

### 3. Monitor Scanning
```bash
# Watch scan progress
python scripts/monitor_scan.py \
  --staging-bucket capsa-staging-intake-YOUR_ACCOUNT_ID \
  --clean-bucket capsa-prod-data-YOUR_ACCOUNT_ID \
  --quarantine-bucket capsa-quarantine-YOUR_ACCOUNT_ID \
  --watch
```

### 4. View Results
```bash
# List clean files
aws s3 ls s3://capsa-prod-data-YOUR_ACCOUNT_ID/ --recursive

# List quarantined files
aws s3 ls s3://capsa-quarantine-YOUR_ACCOUNT_ID/ --recursive

# Get quarantine metadata
aws s3api head-object \
  --bucket capsa-quarantine-YOUR_ACCOUNT_ID \
  --key test-data/malware/eicar_sample_000000.bin \
  --query TagSet
```

## File Structure

```
infrastructure/
├── main.tf                 # Core infrastructure (buckets, KMS, Lambda)
├── iam.tf                 # IAM roles and policies
├── lambda.tf              # Lambda function definitions
├── variables.tf           # Variable definitions
├── terraform.tfvars.example  # Configuration template
├── README.md              # This file
├── scan_trigger.zip       # Packaged scan-trigger Lambda
└── routing_engine.zip     # Packaged routing-engine Lambda

../lambda_functions/
├── scan_trigger/
│   └── index.py          # File scan orchestration
└── routing_engine/
    └── index.py          # File routing logic

../scripts/
├── deploy.sh             # Main deployment script
├── generate_test_data.py # Test data generation
└── monitor_scan.py       # Scan monitoring
```

## Configuration

### Environment Variables
Set in `terraform.tfvars`:

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| aws_region | string | Yes | AWS region (default: us-east-1) |
| environment | string | Yes | Environment name (dev/staging/prod) |
| jira_url | string | Yes | Jira Cloud URL |
| jira_api_token | string | Yes | Jira API token |
| jira_project_key | string | No | Jira project key (default: SEC) |
| virustotal_api_key | string | No | VirusTotal API key |
| alert_email | string | Yes | Email for alerts |
| slack_webhook_url | string | No | Slack webhook for alerts |
| lambda_timeout | number | No | Lambda timeout seconds (default: 300) |
| lambda_memory | number | No | Lambda memory MB (default: 1024) |
| max_concurrent_scans | number | No | Concurrent scans (default: 20) |
| scan_timeout | number | No | Per-file scan timeout (default: 30) |

## IAM Roles Created

### 1. capsa-lambda-scan-trigger-role
Lambda execution role for scan trigger function:
- Read from staging bucket
- Write to quarantine bucket
- Publish to SNS
- Decrypt KMS

### 2. capsa-lambda-scan-engine-role
Lambda execution role for routing engine:
- Read from staging bucket
- Write to clean and quarantine buckets
- Encrypt/decrypt with KMS
- Run ECS tasks for ClamAV
- Publish to SNS

### 3. capsa-migration-team
Role for migration teams to upload files:
- Write to staging bucket only
- Encrypt with KMS

### 4. capsa-security-team-readonly
Role for security analysts:
- Read quarantine bucket
- Query Security Hub
- View CloudWatch metrics

## Monitoring & Alerts

### CloudWatch Alarms
- Lambda errors (> 5 in 5 minutes)
- Lambda duration (> 60 seconds average)
- Malware detections (SNS email/Slack)

### SNS Topics
- Security alerts (malware detections, errors)
- Subscribe with email, Slack, or PagerDuty

### CloudWatch Logs
- `/aws/lambda/capsa-file-scan-trigger`: Scan logs (30-day retention)
- `/aws/lambda/capsa-file-routing-engine`: Routing logs (30-day retention)

## Security Best Practices

### Network Isolation
```bash
# (Optional) Use VPC endpoints for private S3 access
# Uncomment vpc_config in lambda.tf and provide subnet_ids and security_group_ids
```

### Audit Logging
- CloudTrail enabled with 7-year retention
- All S3 API calls logged
- CloudWatch logs for Lambda execution

### Encryption
- KMS keys for each zone (separate key rotation)
- TLS 1.2+ enforced for all data in transit
- S3 bucket policies enforce secure transport

### Access Control
- Principle of least privilege
- Separate IAM roles for each function
- No public access to S3 buckets
- VPC endpoints for private access (optional)

## Troubleshooting

### Lambda Functions Not Triggering
```bash
# Check S3 event notification
aws s3api get-bucket-notification-configuration \
  --bucket capsa-staging-intake-YOUR_ACCOUNT_ID

# Verify Lambda permission
aws lambda get-policy \
  --function-name capsa-file-scan-trigger
```

### S3 Bucket Access Errors
```bash
# Verify KMS key permissions
aws kms describe-key --key-id alias/capsa-staging-key

# Check bucket policy
aws s3api get-bucket-policy \
  --bucket capsa-staging-intake-YOUR_ACCOUNT_ID
```

### No SNS Alerts
```bash
# Verify topic exists
aws sns list-topics

# Check subscriptions
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:capsa-security-alerts

# Publish test message
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:capsa-security-alerts \
  --subject "Test Alert" \
  --message "This is a test message"
```

## Cost Estimation

### Initial Setup (One-time)
- S3 buckets: $0
- KMS keys: $1/key (3 keys) = $3
- Lambda: ~$0 (free tier)
- CloudTrail: $2

**Total: ~$5**

### Monthly Operational Costs (1TB/month data)
- S3 storage: $23 (0.023 $/GB × 1000 GB)
- S3 requests: $5
- KMS: $150 ($1 per key + $0.03 per 10k requests)
- Lambda: $20
- CloudWatch: $30

**Total: ~$230/month**

## Cleanup

### Destroy Infrastructure
```bash
./scripts/deploy.sh prod destroy
```

**WARNING:** This will:
- Delete all S3 buckets (including quarantine with S3 Object Lock)
- Delete KMS keys
- Delete Lambda functions
- Delete IAM roles
- Delete CloudTrail

## Advanced Configuration

### Enable VPC Endpoints (for Private S3 Access)
```bash
# In variables.tf, uncomment and set:
vpc_config {
  subnet_ids         = ["subnet-xxx", "subnet-yyy"]
  security_group_ids = ["sg-xxx"]
}
```

### Enable ClamAV on ECS Fargate
```bash
# Create ECS cluster and task definition
# Update routing_engine to invoke ECS tasks
# See CAPSA_HEALTHCARE_SETUP.md for full ClamAV configuration
```

### Integrate with Jira Cloud
```bash
# Lambda functions automatically create tickets
# Configure in terraform.tfvars:
# - jira_url
# - jira_api_token
# - jira_project_key

# Tickets include:
# - File details (path, hashes, size)
# - Detection info (engine, threat, timestamp)
# - Quarantine link
# - Review workflow
```

## Support

For issues:
1. Check CloudWatch logs: `aws logs tail /aws/lambda/capsa-file-scan-trigger --follow`
2. Review Terraform state: `terraform show`
3. Verify IAM permissions: `aws iam list-attached-role-policies --role-name capsa-lambda-scan-trigger-role`

## References

- [CAPSA Healthcare Setup Guide](../CAPSA_HEALTHCARE_SETUP.md)
- [OpenSecOps-Analyzer README](../README.md)
- [AWS Terraform Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [HIPAA Compliance on AWS](https://aws.amazon.com/compliance/hipaa/)
