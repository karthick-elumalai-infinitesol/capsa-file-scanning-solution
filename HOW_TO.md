# CAPSA — Cloud Application Security Analyzer

Enterprise file scanning pipeline: files enter via SFTP, are scanned by ClamAV on ECS Fargate, and routed to clean or quarantine buckets with full audit trail.

---

## 1. Architecture

```
                        ┌─────────────────────────────────────────────────────────────┐
                        │                     AWS Account 203733861310                 │
                        │                         Region: us-east-2                   │
                        │                                                             │
  ┌──────────┐          │  ┌──────────────┐    ┌─────────────┐    ┌───────────────┐   │
  │ Partners  │─────────│─→│ S3 Staging   │───→│ Lambda      │───→│ Redis Queue   │   │
  │ (SFTP)    │  SFTP   │  │ (Inbound)    │    │ scan-trigger│    │ (ECS Fargate) │   │
  └──────────┘  :2022   │  └──────────────┘    └─────────────┘    └──────┬────────┘   │
                         │                                               │            │
                         │                                               ▼            │
                         │                                        ┌──────────────┐   │
                         │                                        │ Queue Worker │   │
                         │                                        │ (ECS Fargate)│   │
                         │                                        │  + ClamAV    │   │
                         │                                        └──────┬───────┘   │
                         │                                               │            │
                         │                                ┌──────────────┴──────┐    │
                         │                                ▼                     ▼    │
                         │                        ┌──────────────┐    ┌──────────────┐│
                         │                        │ S3 Clean     │    │ S3 Quarantine││
                         │                        │ (Scanned OK) │    │ (Malware)    ││
                         │                        └──────────────┘    │ Object Lock  ││
                         │                                            │ 7yr Retention││
                         │                                            └──────────────┘│
                         │                                                             │
                         │  GuardDuty · CloudTrail · SNS Alerts · KMS Encryption      │
                         └─────────────────────────────────────────────────────────────┘
```

### Pipeline Flow

| Step | Component | Action |
|------|-----------|--------|
| 1 | SFTPGo (ECS) | Partner uploads file to S3 Staging via SFTP port 2022 |
| 2 | Lambda (scan-trigger) | S3 event → enqueues object key to Redis |
| 3 | Queue Worker (ECS) | Pulls from Redis → downloads from S3 → streams to ClamAV |
| 4 | ClamAV (ECS) | Scans stream for malware signatures |
| 5 | Lambda (routing-engine) | Clean → S3 Clean bucket; Infected → S3 Quarantine with tags |
| 6 | SNS | Email alert on threat detection |
| 7 | Reports | Daily CSV → S3 Reports bucket |

### AWS Resources Deployed

| Resource | Description |
|----------|-------------|
| S3 Buckets | `capsa-staging-*`, `capsa-clean-*`, `capsa-quarantine-*`, `capsa-reports-*` |
| ECS Fargate | ClamAV, Redis, SFTPGo, Queue Worker (4 services, 1 task each) |
| Lambda | scan-trigger, routing-engine, report-generator |
| Security | KMS keys, VPC endpoints (S3, Secrets Manager, CloudWatch), GuardDuty, CloudTrail |
| Networking | Security groups, VPC endpoints, route tables |
| Monitoring | CloudWatch log groups, SNS alert topic |

---

## 2. File Upload Methods

### Method 1: SFTP (Production — Primary Intake)

Partners upload files via SFTP to port **2022**. SFTPGo writes directly to the S3 staging bucket.

```bash
sftp -P 2022 <partner-username>@<sftp-host>
put /path/to/file.csv ./incoming/
```

Each partner has an isolated home directory on S3 (prefix: `partners/<partner-id>/`). Files are automatically picked up by the scan pipeline.

### Method 2: AWS CLI Direct to S3

```bash
# Upload to staging bucket — pipeline processes automatically
aws s3 cp file.txt s3://capsa-staging-203733861310/incoming/

# Check results in clean bucket
aws s3 ls s3://capsa-clean-203733861310/ --recursive

# Check quarantined files
aws s3 ls s3://capsa-quarantine-203733861310/ --recursive
```

### Method 3: REST API (Local Dev)

```bash
# Start the API
uvicorn src.main:app --reload

# Upload a file for scanning (in-memory scan, no S3 persistence)
curl -X POST -F "file=@document.pdf" http://localhost:8000/scan/local-file
```

---

## 3. User Dashboard

Access the operations dashboard at **`http://<host>:8000/dashboard`** (or load-balanced URL in production).

### Dashboard Features

| Section | Data Source | What It Shows |
|---------|------------|---------------|
| Bucket Cards | S3 API | Object counts and size for staging, clean, quarantine |
| Throughput | Real-time | Total files processed |
| SFTP Server | SFTPGo API | Version, uptime, active connections, partner count |
| Pipeline Flow | Static | Visual 4-step pipeline (Upload → Scan → Route → Report) |
| Threats Table | S3 quarantine + tags | File name, threat name, partner, batch ID, status |
| Partners Table | SFTPGo API | Username, company, home dir, auth method |
| System Health | Composite | SFTPGo, S3, ClamAV, SNS status indicators |

The dashboard auto-refreshes every 10 seconds.

### API Endpoints (used by dashboard)

| Endpoint | Returns |
|----------|---------|
| `GET /api/aws/buckets` | S3 bucket object counts and sizes |
| `GET /api/aws/quarantine-files` | Quarantined files with threat/source tags |
| `GET /api/aws/detection-summary` | Breakdown by threat name and partner company |
| `GET /api/sftp/status` | SFTPGo server health |
| `GET /api/sftp/users` | Provisioned SFTP partner accounts |
| `GET /api/report/csv` | CSV export of scan performance history |

---

## 4. Quick Start (Local Development)

```bash
# Python environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start API
uvicorn src.main:app --reload    # http://localhost:8000
uvicorn dashboard_ui.app:app --reload --port 8001   # Dashboard at http://localhost:8001/dashboard
```

### Docker (Local Stack)

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
# Services: API :8000, ClamAV :3310, SFTPGo :2222, Redis :6379
```

---

## 5. Production Deployment

### Prerequisites
- AWS CLI configured (admin or sufficient permissions)
- Terraform >= 1.0
- Existing VPC with at least 2 private subnets

### Deploy

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: vpc_id, subnet_ids, alert_email
cd ..

./scripts/deploy.sh prod plan
./scripts/deploy.sh prod apply
```

### Verify Deployment

```bash
# Check ECS services are active
aws ecs describe-services --cluster capsa-prod-clamav-cluster --services capsa-prod-clamav-service

# Upload a test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
aws s3 cp /tmp/eicar.txt s3://capsa-staging-<ACCOUNT_ID>/test/eicar.txt

# Watch it flow through the pipeline
aws logs tail /aws/lambda/capsa-prod-file-scan-trigger --follow

# Verify quarantine
aws s3 ls s3://capsa-quarantine-<ACCOUNT_ID>/ --recursive
```

### Destroy

```bash
./scripts/deploy.sh prod destroy
```

---

## 6. Production Security Checklist

- [ ] Use IAM roles (not hardcoded access keys) for all AWS SDK clients
- [ ] Rotate SFTPGo admin password from default (`change-me-in-production`)
- [ ] Restrict S3 bucket policies to minimal required principals
- [ ] Enable S3 Object Lock on quarantine bucket for WORM compliance
- [ ] Configure VPC flow logs and CloudTrail for audit
- [ ] Set up CloudWatch alarms for pipeline failures
- [ ] Use AWS Secrets Manager or Parameter Store for secrets
- [ ] Enforce TLS 1.2+ on all API endpoints
- [ ] Regular ClamAV virus definition updates (container auto-pulls on restart)
- [ ] Disaster recovery: cross-region bucket replication for clean/quarantine

---

## 7. Configuration Reference

### `.env` (Local Development)

| Variable | Purpose |
|----------|---------|
| `AWS_REGION` | AWS region (default: us-east-2) |
| `AWS_STAGING_BUCKET` | S3 staging bucket name |
| `AWS_CLEAN_BUCKET` | S3 clean bucket name |
| `AWS_QUARANTINE_BUCKET` | S3 quarantine bucket name |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (optional) |
| `SFTPGO_URL` | SFTPGo admin API URL |
| `SFTPGO_ADMIN_USER` | SFTPGo admin username |
| `SFTPGO_ADMIN_PASSWORD` | SFTPGo admin password |
| `LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR |
| `MAX_WORKERS` | Scanner thread pool size (default: 20) |

### `terraform.tfvars` (Production)

| Variable | Purpose |
|----------|---------|
| `aws_region` | AWS region |
| `environment` | Environment name (prod/dev) |
| `vpc_id` | Existing VPC ID |
| `subnet_ids` | Private subnet IDs for Lambda/ECS |
| `alert_email` | SNS alert email for threat notifications |

---

## 8. Troubleshooting

| Symptom | Check |
|---------|-------|
| Files stuck in staging | Lambda logs: `aws logs tail /aws/lambda/capsa-prod-file-scan-trigger` |
| No S3 event notification | Verify `s3:ObjectCreated:*` events on staging bucket |
| ECS tasks not starting | Verify VPC/subnet IDs, task role permissions, CloudWatch logs |
| ClamAV not responding | `aws ecs describe-services --cluster capsa-prod-clamav-cluster --services capsa-prod-clamav-service` |
| GuardDuty not detecting | Ensure detector ID matches environment |
| Dashboard SFTP shows offline | Check `SFTPGO_URL` config, network connectivity to port 8080/8090 |
| Terraform subnet error | Verify subnet IDs exist in the specified VPC |
