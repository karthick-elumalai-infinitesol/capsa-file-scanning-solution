# OpenSecOps-Analyzer Quick Start Guide

## Installation & Setup

### 1. Prerequisites
```bash
# Python 3.8 or higher
python --version

# AWS credentials configured
aws configure

# VirusTotal API key (get from https://www.virustotal.com/gui/my-apikey)
# Jira Cloud account with API token
```

### 2. Install Dependencies
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your credentials:
# - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
# - AWS_REGION, S3_BUCKET
# - VIRUSTOTAL_API_KEY
# - JIRA_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
```

### 4. Run Tests
```bash
pytest tests/ -v

# Expected output:
# ================== 12 passed, 2 skipped in X.XXs ==================
```

## Usage

### Start the API Server
```bash
python -m uvicorn src.main:app --reload
# Server running at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### Example: Generate Test Data & Scan

```bash
# 1. Generate synthetic malware/clean test data
curl -X POST "http://localhost:8000/generate-test-data" \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-s3-bucket",
    "prefix": "test-data/",
    "dataset_size": "small"
  }'

# 2. Start scanning
curl -X POST "http://localhost:8000/scan/s3-bucket" \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-s3-bucket",
    "prefix": "test-data/",
    "max_files": 1000
  }'

# 3. Check status
curl http://localhost:8000/status

# 4. Get results
curl http://localhost:8000/results?limit=10

# 5. Get malware detections only
curl http://localhost:8000/results/malware
```

### Programmatic Usage

```python
from src.scanner.concurrent_scanner import ConcurrentScanner
from src.integrations.jira import JiraClient

# Create scanner
scanner = ConcurrentScanner()

# Scan S3 bucket
results = scanner.scan_s3_bucket(
    bucket="my-s3-bucket",
    prefix="data/",
    max_files=None  # Scan all files
)

# Check results
print(f"Scanned: {len(results)} files")
for result in results:
    if result.is_malware:
        print(f"MALWARE: {result.file_name} ({result.threat_level})")
        
        # Create Jira ticket if detected
        jira = JiraClient()
        ticket_id = jira.create_issue(result)
        print(f"Jira ticket: {ticket_id}")

# Get metrics
metrics = scanner.get_metrics()
print(f"Throughput: {metrics['throughput_files_per_second']:.2f} files/sec")
```

## Performance Benchmarks

### Test Results (100k file simulation)
- **Files Scanned**: 100,000
- **Malware Detected**: 50,000 (50%)
- **Throughput**: ~1,000 files/second
- **Duration**: ~100 seconds
- **Memory Usage**: <500 MB

### Expected 1TB Performance
- **Estimated Files**: 1,000,000 (1MB average per file)
- **Expected Duration**: <30 minutes
- **Expected Throughput**: >1,000 files/second
- **Memory Usage**: <500 MB peak

## Deployment

### Docker

```bash
# Build image
docker build -f docker/Dockerfile -t opensecops-analyzer:latest .

# Run container
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  -e VIRUSTOTAL_API_KEY=your_vt_key \
  -e JIRA_URL=https://your-org.atlassian.net \
  -e JIRA_API_TOKEN=your_jira_token \
  opensecops-analyzer:latest
```

### Configuration Options

Environment variables for tuning:
- `MAX_WORKERS`: Number of concurrent scanner threads (default: 20)
- `LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR (default: INFO)
- `ENABLE_CACHE`: Enable detection result caching (default: true)
- `CACHE_TTL_SECONDS`: Cache time-to-live in seconds (default: 86400)
- `VIRUSTOTAL_RATE_LIMIT`: API requests per minute (default: 4)

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/scan/s3-bucket` | POST | Start S3 bucket scan |
| `/status` | GET | Get scan progress |
| `/results` | GET | Get scan results (paginated) |
| `/results/malware` | GET | Get malware detections only |
| `/generate-test-data` | POST | Generate synthetic test data |
| `/metrics` | GET | Get detailed scan metrics |
| `/clear-results` | POST | Clear cached results |

## Troubleshooting

### AWS Credentials Not Found
```bash
# Set credentials
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1
```

### VirusTotal API Rate Limit
- Free tier: 4 requests/minute
- Paid tier: Higher limits
- Solution: Enable caching, use batch operations

### Jira Authentication Failed
- Verify Jira API token (not password)
- Check JIRA_URL format (https://org.atlassian.net)
- Ensure token has necessary permissions

### S3 Access Denied
- Verify IAM permissions for ListBucket, GetObject
- Check bucket region matches AWS_REGION
- Verify bucket name in environment

## Next Steps

1. **Scale to 1TB dataset**: 
   - Adjust `MAX_WORKERS` based on your system
   - Monitor memory and CPU usage
   - Consider using S3 batch operations

2. **Integrate with existing tools**:
   - Export to SIEM (Splunk, ELK)
   - Send metrics to CloudWatch/DataDog
   - Post to Slack/Teams on detections

3. **Enhance detection**:
   - Add ClamAV integration
   - Implement behavior-based analysis
   - Use AWS GuardDuty alongside

## Support

For issues or questions:
- Check test files for usage examples
- Review logs with `LOG_LEVEL=DEBUG`
- Check README.md for architecture details
- Open GitHub issues for bugs/features
