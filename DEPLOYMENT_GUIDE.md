# CAPSA Healthcare - Complete Deployment Guide

Deploy the OpenSecOps-Analyzer on AWS with full 3-zone architecture, dual-engine scanning (GuardDuty + ClamAV), and HIPAA-compliant quarantine.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Test Data Generation](#test-data-generation)
5. [Monitoring & Validation](#monitoring--validation)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

Deploy in 30 minutes:

```bash
# 1. Clone or navigate to repository
cd OpenSecOps-Analyzer

# 2. Configure Terraform
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values (Jira, VirusTotal, email)

# 3. Deploy infrastructure
cd ..
./scripts/deploy.sh prod plan      # Review changes
./scripts/deploy.sh prod apply     # Deploy

# 4. Generate test data (optional)
python scripts/generate_test_data.py --bucket capsa-staging-intake-YOUR_ACCOUNT_ID --size 0.01

# 5. Monitor progress
python scripts/monitor_scan.py --staging-bucket capsa-staging-intake-YOUR_ACCOUNT_ID \
  --clean-bucket capsa-prod-data-YOUR_ACCOUNT_ID \
  --quarantine-bucket capsa-quarantine-YOUR_ACCOUNT_ID --watch
```

---

## Prerequisites

### Software Requirements

```bash
# Required
terraform >= 1.0
aws-cli >= 2.0
python >= 3.8
git

# Recommended
jq (for JSON parsing)
curl (for API testing)

# Installation
# macOS
brew install terraform awscli python jq curl

# Ubuntu/Debian
sudo apt-get install terraform awscli python3 jq curl

# Verify installation
terraform version
aws --version
python3 --version
```

### AWS Account Setup

```bash
# 1. Create AWS account (if not existing)
# https://aws.amazon.com/

# 2. Configure AWS CLI
aws configure

# Enter when prompted:
# AWS Access Key ID: [your-key]
# AWS Secret Access Key: [your-secret]
# Default region: us-east-1
# Default output format: json

# 3. Verify credentials
aws sts get-caller-identity

# Should output your account ID and ARN
```

### Jira Cloud Setup

```bash
# 1. Create Jira project (if not existing)
# https://www.atlassian.com/

# 2. Create API token
# Settings → Security → API tokens → Create API token

# 3. Store credentials
# Will be added to terraform.tfvars in next step
```

### VirusTotal (Optional)

```bash
# Get API key
# https://www.virustotal.com/gui/home/upload

# Free tier: 4 requests/minute
# Pro tier: 500 requests/minute
```

---

## Infrastructure Setup

### Step 1: Configure Terraform

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
aws_region = "us-east-1"
environment = "prod"

# Jira Cloud Configuration
jira_url = "https://your-company.atlassian.net"
jira_api_token = "xxxxx"  # From Settings → Security → API tokens
jira_project_key = "SEC"

# VirusTotal Configuration (optional)
virustotal_api_key = "xxxxx"

# Alerting Configuration
alert_email = "security-team@your-company.com"
# slack_webhook_url = "https://hooks.slack.com/..."  # Optional

# Lambda Configuration (optional)
# lambda_timeout = 300
# lambda_memory = 1024
```

### Step 2: Validate Configuration

```bash
cd ..
./scripts/deploy.sh prod validate

# Should output:
# ✅ All prerequisites met
# ✅ Configuration validated
# ✅ Terraform initialized
# ✅ Terraform configuration valid
```

### Step 3: Plan Deployment

```bash
./scripts/deploy.sh prod plan

# Review the Terraform plan output
# Verify all resources to be created
```

Expected resources:
- 5 S3 buckets (staging, clean, quarantine, logs, cloudtrail)
- 3 KMS encryption keys
- 2 Lambda functions
- 1 SNS topic
- 1 GuardDuty detector
- CloudWatch log groups
- CloudTrail
- IAM roles and policies

### Step 4: Deploy Infrastructure

```bash
./scripts/deploy.sh prod apply

# This will:
# 1. Create all S3 buckets with encryption
# 2. Set up KMS keys
# 3. Deploy Lambda functions
# 4. Configure SNS alerts
# 5. Enable CloudTrail
# 6. Create IAM roles
# Duration: 5-10 minutes
```

### Step 5: Verify Deployment

```bash
# Get output information
./scripts/deploy.sh prod output

# Expected output:
# staging_bucket_name = "capsa-staging-intake-123456789"
# clean_bucket_name = "capsa-prod-data-123456789"
# quarantine_bucket_name = "capsa-quarantine-123456789"
# sns_topic_arn = "arn:aws:sns:..."
# guardduty_detector_id = "..."

# Store these values for next steps
export STAGING_BUCKET="capsa-staging-intake-123456789"
export CLEAN_BUCKET="capsa-prod-data-123456789"
export QUARANTINE_BUCKET="capsa-quarantine-123456789"
```

### Step 6: Confirm SNS Subscription

Check your email for SNS subscription confirmation:

```
AWS Notification - Subscription Confirmation
You have chosen to subscribe to...
Click here to confirm subscription
```

Click the link to confirm and start receiving alerts.

---

## Test Data Generation

### Generate Small Test Dataset (Quick Test)

```bash
# Generate 10MB of test data (quick, ~1 minute)
python scripts/generate_test_data.py \
  --bucket $STAGING_BUCKET \
  --size 0.01 \
  --prefix test-data
```

### Generate Full 1TB Test Dataset

```bash
# Generate complete 1TB dataset (50% malware, 50% clean)
# Duration: 2-3 hours on average connection
python scripts/generate_test_data.py \
  --bucket $STAGING_BUCKET \
  --size 1.0 \
  --prefix test-data

# Monitor progress:
# The script will output progress every 100 files
# Example:
# 10.5% - 1050 files - 1024 MB
# 20.3% - 2031 files - 2048 MB
```

### Verify Upload

```bash
# List uploaded files
aws s3 ls s3://$STAGING_BUCKET/test-data/ --recursive --summarize

# Expected output:
# Total Objects: 1,000,000
# Total Size: 1099511627776 bytes (1.0 TB)

# Count files by type
aws s3 ls s3://$STAGING_BUCKET/test-data/malware/ --recursive | wc -l
aws s3 ls s3://$STAGING_BUCKET/test-data/clean/ --recursive | wc -l
```

---

## Monitoring & Validation

### Real-Time Monitoring

```bash
# Start continuous monitoring (updates every 30 seconds)
python scripts/monitor_scan.py \
  --staging-bucket $STAGING_BUCKET \
  --clean-bucket $CLEAN_BUCKET \
  --quarantine-bucket $QUARANTINE_BUCKET \
  --watch

# Output shows:
# - Files in staging (inbound)
# - Files moved to clean bucket (passed scan)
# - Files quarantined (detected as malware)
# - Lambda function metrics (invocations, errors, duration)
```

### One-Time Status Check

```bash
# Get current status (no continuous monitoring)
python scripts/monitor_scan.py \
  --staging-bucket $STAGING_BUCKET \
  --clean-bucket $CLEAN_BUCKET \
  --quarantine-bucket $QUARANTINE_BUCKET
```

### View Scan Results

```bash
# Clean files (passed scan)
aws s3 ls s3://$CLEAN_BUCKET/ --recursive | head -20

# Quarantined files (detected malware)
aws s3 ls s3://$QUARANTINE_BUCKET/ --recursive | head -20

# Get file metadata
aws s3api head-object \
  --bucket $QUARANTINE_BUCKET \
  --key test-data/malware/eicar_sample_000000.bin \
  --query Metadata

# Get file tags
aws s3api get-object-tagging \
  --bucket $QUARANTINE_BUCKET \
  --key test-data/malware/eicar_sample_000000.bin
```

### Check Lambda Logs

```bash
# View scan trigger logs (last 100 lines)
aws logs tail /aws/lambda/capsa-file-scan-trigger --follow --lines 100

# View routing engine logs
aws logs tail /aws/lambda/capsa-file-routing-engine --follow --lines 100
```

### View Jira Tickets

```bash
# List created tickets in Jira
curl -u user@example.com:API_TOKEN https://your-domain.atlassian.net/rest/api/3/search?jql=project=SEC

# Or log into Jira and navigate to:
# Projects → SEC → Issues
# Filter by label: "malware" or "quarantine-review"
```

---

## Performance Validation

### Expected Metrics (1TB Dataset)

```
File Processing:
- Files per second: 1,000+
- Average file size: 1 MB
- Total files: ~1,000,000
- Estimated completion: 15-30 minutes

Detection Accuracy:
- Malware detection rate: >95%
- False positive rate: <2%
- EICAR detection: 100%

System Performance:
- Lambda memory peak: <500 MB per invocation
- Lambda average duration: 100-500 ms per file
- S3 API call latency: <50 ms average
- SNS notification latency: <5 seconds
```

### Benchmark Test

```bash
# Quick benchmark with 100 files
python scripts/generate_test_data.py \
  --bucket $STAGING_BUCKET \
  --size 0.0001 \
  --prefix benchmark

# Monitor with watch
python scripts/monitor_scan.py \
  --staging-bucket $STAGING_BUCKET \
  --clean-bucket $CLEAN_BUCKET \
  --quarantine-bucket $QUARANTINE_BUCKET \
  --watch

# Calculate throughput
# Files processed / Total time = files/second
```

---

## Production Deployment

### Pre-Production Checklist

```bash
# ✅ Infrastructure deployed and verified
terraform show | grep resource | wc -l
# Should show: 25+ resources

# ✅ Test data uploaded and scanning working
aws s3 ls s3://$STAGING_BUCKET/ --summarize | grep "Total Objects"

# ✅ SNS alerts configured
aws sns list-subscriptions-by-topic --topic-arn $(aws sns list-topics | grep capsa-security-alerts | cut -d'"' -f4) | grep "Email"

# ✅ CloudTrail enabled and logging
aws cloudtrail describe-trails --query 'trailList[0].IsLogging'

# ✅ Jira integration configured
grep -v "^#" infrastructure/terraform.tfvars | grep jira

# ✅ IAM roles configured
aws iam list-roles | grep capsa | wc -l
# Should show: 4 roles
```

### Enable Production Data Upload

```bash
# Migration team uploads to staging bucket
# Files automatically scanned by Lambda
# Malware → Quarantine bucket (with 7-year WORM lock)
# Clean → Production bucket (ready for processing)

# Jira tickets created automatically for detections
```

### Configure Automated Backups

```bash
# Recommend using S3 bucket replication for disaster recovery
# Cross-region replication of quarantine bucket
# Daily snapshots of clean production bucket
```

### Set Up Monitoring & Alerting

```bash
# Subscribe additional email addresses to SNS topic
aws sns subscribe \
  --topic-arn $(aws sns list-topics | grep capsa-security-alerts | cut -d'"' -f4) \
  --protocol email \
  --notification-endpoint user2@example.com

# Confirm subscription in email

# Add Slack webhook for alerts (optional)
aws secretsmanager update-secret \
  --secret-id capsa/slack-webhook \
  --secret-string '{"webhook_url":"https://..."}'
```

### Enable HIPAA Audit Logging

```bash
# Verify CloudTrail is logging all API calls
aws cloudtrail get-event-selectors --trail-name capsa-audit-trail

# View audit logs
aws s3 ls s3://capsa-cloudtrail-123456789/AWSLogs/ --recursive | head -20

# Set up CloudWatch dashboard
# Dashboard → Create dashboard → "CAPSA Security"
# Add widgets for:
# - Files scanned
# - Malware detected
# - Scan errors
# - Lambda performance
```

---

## Scaling to Production

### For Large-Scale Deployments (10TB+/month)

1. **Increase Lambda Resources**
   ```bash
   # Edit infrastructure/terraform.tfvars
   lambda_memory = 3008  # Maximum
   lambda_timeout = 900  # 15 minutes
   max_concurrent_scans = 100
   ```

2. **Enable ClamAV ECS Fargate**
   ```bash
   # Deploy ECS cluster with ClamAV containers
   # Update routing_engine to invoke ECS tasks for secondary scanning
   # See CAPSA_HEALTHCARE_SETUP.md for ClamAV configuration
   ```

3. **Enable S3 Batch Operations**
   ```bash
   # Use S3 Batch Operations for mass scanning
   # Reduces API overhead for large datasets
   ```

4. **Configure Auto-Scaling**
   ```bash
   # Lambda automatically scales with concurrent invocations
   # No additional configuration needed
   # Monitor costs with AWS Cost Explorer
   ```

---

## Troubleshooting

### Lambda Functions Not Triggering

```bash
# 1. Verify S3 event notification
aws s3api get-bucket-notification-configuration \
  --bucket $STAGING_BUCKET

# 2. Verify Lambda permission
aws lambda get-policy --function-name capsa-file-scan-trigger

# 3. Check Lambda logs
aws logs tail /aws/lambda/capsa-file-scan-trigger --follow

# 4. Manual test upload
echo "test file" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://$STAGING_BUCKET/test.txt

# 5. Check logs after upload
aws logs tail /aws/lambda/capsa-file-scan-trigger --follow --lines 50
```

### S3 Encryption Errors

```bash
# 1. Verify KMS key permissions
aws kms describe-key --key-id alias/capsa-staging-key

# 2. Grant Lambda KMS access
aws kms create-grant \
  --key-id alias/capsa-staging-key \
  --grantee-principal arn:aws:iam::ACCOUNT_ID:role/capsa-lambda-scan-trigger-role \
  --operations Encrypt Decrypt GenerateDataKey

# 3. Verify bucket encryption
aws s3api get-bucket-encryption --bucket $STAGING_BUCKET
```

### SNS Alerts Not Arriving

```bash
# 1. Verify SNS topic exists
aws sns list-topics | grep capsa-security-alerts

# 2. List subscriptions
aws sns list-subscriptions-by-topic \
  --topic-arn $(aws sns list-topics | grep capsa-security-alerts | cut -d'"' -f4)

# 3. Confirm subscription
# Check email for confirmation link and click

# 4. Test publish
aws sns publish \
  --topic-arn $(aws sns list-topics | grep capsa-security-alerts | cut -d'"' -f4) \
  --subject "Test Alert" \
  --message "Testing SNS alerts"

# 5. Check spam folder if not received
```

### Object Lock Errors on Quarantine Bucket

```bash
# 1. Verify Object Lock is enabled
aws s3api get-object-lock-configuration --bucket $QUARANTINE_BUCKET

# 2. Check retention settings
aws s3api head-object \
  --bucket $QUARANTINE_BUCKET \
  --key test-data/malware/sample.bin \
  --query ObjectLockRetainUntilDate

# 3. Cannot delete files with active lock
# This is intentional (HIPAA compliance)
# Wait for retention period to expire

# 4. Bypass (AWS CLI requires legal hold removal)
aws s3api put-object-legal-hold \
  --bucket $QUARANTINE_BUCKET \
  --key test-data/malware/sample.bin \
  --legal-hold Status=OFF
```

### Cost Optimization

```bash
# 1. Review AWS Cost Explorer
# AWS Console → Billing → Cost Explorer

# 2. Optimize S3 storage classes
# Move older clean files to Glacier
aws s3 sync s3://$CLEAN_BUCKET/ s3://$CLEAN_BUCKET/ \
  --storage-class GLACIER \
  --exclude '*' --include '*.old'

# 3. Reduce Lambda memory (if possible)
# Edit infrastructure/terraform.tfvars
# lambda_memory = 512  # Minimum

# 4. Use S3 Intelligent-Tiering
# Automatically move unused files to cheaper storage
```

---

## Cleanup & Destruction

### Remove Infrastructure

```bash
# WARNING: This will delete all resources including data in quarantine bucket
./scripts/deploy.sh prod destroy

# Confirm when prompted: type "yes"

# Verify destruction
terraform show | grep resource | wc -l
# Should show: 0 resources
```

### Backup Before Destruction

```bash
# Backup quarantine bucket
aws s3 sync s3://$QUARANTINE_BUCKET/ ./backup/quarantine/

# Backup clean bucket
aws s3 sync s3://$CLEAN_BUCKET/ ./backup/clean/

# Backup CloudTrail logs
aws s3 sync s3://capsa-cloudtrail-123456789/ ./backup/cloudtrail/
```

---

## Security Considerations

### IAM Best Practices
- ✅ Least privilege access per role
- ✅ No public S3 bucket access
- ✅ Encryption for all data at rest and in transit
- ✅ CloudTrail logging for audit compliance

### Compliance
- ✅ HIPAA audit trail (CloudTrail + CloudWatch)
- ✅ 7-year quarantine retention (WORM lock)
- ✅ Data encryption (KMS)
- ✅ Access controls (IAM roles)
- ✅ Network isolation (VPC endpoints optional)

### Ongoing Security
1. Rotate KMS keys annually
2. Review CloudTrail logs monthly
3. Update Lambda function code for patches
4. Monitor CloudWatch alarms
5. Test disaster recovery quarterly

---

## Support & Documentation

### References
- [CAPSA Healthcare Setup Guide](./CAPSA_HEALTHCARE_SETUP.md)
- [Infrastructure README](./infrastructure/README.md)
- [OpenSecOps-Analyzer README](./README.md)
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

### Helpful Commands

```bash
# Get account ID
aws sts get-caller-identity --query Account --output text

# Get all S3 buckets
aws s3 ls

# Get Lambda function details
aws lambda get-function --function-name capsa-file-scan-trigger

# Get IAM role policies
aws iam list-inline-role-policies --role-name capsa-lambda-scan-trigger-role

# Get recent CloudTrail events
aws cloudtrail lookup-events --max-results 10

# Get SNS metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/SNS \
  --metric-name NumberOfMessagesPublished \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

### Getting Help

1. Check infrastructure logs: `aws logs tail /aws/lambda/<function-name> --follow`
2. Review Terraform state: `terraform show`
3. Verify AWS credentials: `aws sts get-caller-identity`
4. Check IAM permissions: `aws iam simulate-principal-policy --policy-source-arn ...`
5. Review AWS Service Health: https://status.aws.amazon.com/

---

**Happy scanning! 🔍🚨**
