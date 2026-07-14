# CAPSA — How To Guide

Cloud Application Security Analyzer (CAPSA) scans S3 files for malware using hash-based detection (VirusTotal + NSRL) and ClamAV, with automatic routing (clean / quarantine) and Jira ticketing.

---

## 1. Project Structure

```
.
├── src/                  # Python source code (FastAPI app, scanner, integrations)
├── tests/                # Pytest unit tests
├── test_dataset/         # Sample EICAR malware + clean files for local testing
├── infrastructure/       # Terraform (AWS: S3, Lambda, ECS, VPC endpoints, IAM)
├── lambda_functions/     # Lambda source code (scan_trigger, routing_engine, report_generator)
├── docker/               # Docker Compose (ClamAV + FastAPI)
├── dashboard_ui/         # Web dashboard (FastAPI + HTML/JS/CSS)
├── scripts/              # Utility scripts (deploy, monitor, generate data)
├── HOW_TO.md             # This file
├── README.md             # Full project overview
├── QUICKSTART.md         # Quick start guide
├── RUN_LOCALLY.md        # Detailed local run instructions
├── DOWNLOAD_AND_RUN.md   # Download & run guide
├── DEPLOYMENT_GUIDE.md   # Production deployment guide
├── requirements.txt      # Python dependencies
└── .env.example          # Environment template (copy to .env)
```

---

## 2. Quick Start (Local, No AWS)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python test_local.py                          # Scan local test dataset
pytest tests/ -v                              # Run unit tests
python -m uvicorn src.main:app --reload       # Start API at localhost:8000
```

---

## 3. Docker (ClamAV + Scanner)

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
# API at http://localhost:8000
# ClamAV at clamav:3310 (inside compose network)
```

---

## 4. AWS Deployment (Terraform)

### Prerequisites
- AWS CLI configured with admin credentials
- Terraform >= 1.0

### Deploy

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
cd ..

# Plan + Apply
./scripts/deploy.sh prod plan
./scripts/deploy.sh prod apply
```

Creates: S3 buckets (staging, clean, quarantine, reports), Lambda functions (scan trigger, routing engine, report generator), ECS cluster (ClamAV, Redis, SFTPGo, Queue Worker), VPC endpoints, GuardDuty, CloudTrail, SNS alerts.

### Destroy

```bash
./scripts/deploy.sh prod destroy
```

---

## 5. API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/scan/s3-bucket` | POST | Start S3 bucket scan |
| `/status` | GET | Scan progress |
| `/results` | GET | Scan results (paginated) |
| `/results/malware` | GET | Malware detections only |
| `/generate-test-data` | POST | Generate test data |
| `/metrics` | GET | Scanner metrics |
| `/clear-results` | POST | Clear cached results |

---

## 6. Testing the Pipeline

### Upload test files to staging bucket:

```bash
# EICAR (malware)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
aws s3 cp /tmp/eicar.txt s3://capsa-staging-<ACCOUNT_ID>/test/eicar.txt

# Clean file
echo "clean data" > /tmp/clean.txt
aws s3 cp /tmp/clean.txt s3://capsa-staging-<ACCOUNT_ID>/test/clean.txt
```

### Check results:

```bash
# Clean files move here
aws s3 ls s3://capsa-clean-<ACCOUNT_ID>/ --recursive

# Malware files move here
aws s3 ls s3://capsa-quarantine-<ACCOUNT_ID>/ --recursive
```

### Monitor Lambda logs:

```bash
aws logs tail /aws/lambda/capsa-prod-file-scan-trigger --follow
aws logs tail /aws/lambda/capsa-prod-file-routing-engine --follow
```

---

## 7. Configuration

### .env (local)

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region |
| `AWS_STAGING_BUCKET` | S3 staging bucket |
| `AWS_CLEAN_BUCKET` | S3 clean bucket |
| `AWS_QUARANTINE_BUCKET` | S3 quarantine bucket |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `JIRA_URL` | Jira Cloud URL |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Jira project key |
| `MAX_WORKERS` | Scanner threads (default: 20) |
| `LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR |

### terraform.tfvars

| Variable | Description |
|---|---|
| `aws_region` | AWS region |
| `environment` | Environment name (prod/dev) |
| `vpc_id` | Existing VPC ID |
| `subnet_ids` | Subnet IDs for Lambda/ECS |
| `jira_url` | Jira Cloud URL |
| `jira_api_token` | Jira API token |
| `alert_email` | SNS alert email |

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Lambda not triggering | Check S3 event notification on staging bucket |
| Files stuck in staging | Check Lambda logs for errors |
| ClamAV not responding | `aws ecs describe-services --cluster capsa-prod-clamav-cluster --services capsa-prod-clamav-service` |
| ECS tasks not starting | Check VPC/subnet IDs in terraform.tfvars |
| GuardDuty not finding threats | Detector ID must match environment |
| Terraform subnet error | Verify subnet IDs exist in the VPC |

---

## 9. Key Commands Reference

```bash
# Local
python test_local.py                          # Quick local test
pytest tests/ -v                              # Unit tests
python -m uvicorn src.main:app --reload       # API server

# Docker
docker compose -f docker/docker-compose.yml up --build

# AWS
aws s3 ls s3://capsa-staging-<ACCOUNT_ID>/    # List staging files
aws logs tail /aws/lambda/capsa-prod-file-scan-trigger --follow  # Lambda logs
aws ecs list-tasks --cluster capsa-prod-clamav-cluster            # ECS tasks

# Terraform
./scripts/deploy.sh prod plan                  # Plan changes
./scripts/deploy.sh prod apply                 # Apply changes
./scripts/deploy.sh prod destroy               # Destroy all
```
