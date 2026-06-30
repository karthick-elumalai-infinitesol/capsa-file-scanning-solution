# Running OpenSecOps-Analyzer Locally

Complete guide to download, extract, and run OpenSecOps-Analyzer on your machine.

## Download & Extract

### Option 1: Download Zip File

1. Download `OpenSecOps-Analyzer.zip` 
2. Extract the zip file:
   ```bash
   unzip OpenSecOps-Analyzer.zip
   cd OpenSecOps-Analyzer
   ```

### Option 2: Clone from Git

```bash
git clone https://github.com/ek2020/OpenSecOps-Analyzer.git
cd OpenSecOps-Analyzer
git checkout claude/admiring-darwin-s6maxl
```

## Quick Start (Local Testing - No AWS Needed)

### 1. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Local Tests (Included Test Dataset)

The project includes a test dataset with 10 malware samples (EICAR) and 10 clean files.

```bash
# Run local file scanner
python test_local.py

# Expected output:
# ✅ Scans 21 files (10 clean + 11 with EICAR signatures)
# ✅ Shows detection results with file hashes
# ✅ Displays summary statistics
```

### 3. Run Unit Tests

```bash
# All tests (12 passing)
pytest tests/ -v

# Specific test file
pytest tests/test_scanner.py -v

# With coverage
pytest tests/ --cov=src
```

### 4. Run the Docker Compose ClamAV stack

This project now supports a local two-container setup where the FastAPI scanner streams
file bytes directly to ClamAV over TCP port `3310` using ClamAV's `INSTREAM` protocol.

```bash
# Create local environment file first
cp .env.example .env

# Start ClamAV + scanner API
docker compose -f docker/docker-compose.yml up --build
```

How it works locally:
- `scanner` exposes the API on `http://localhost:8000`
- `clamav` listens on `clamav:3310` inside Docker Compose
- the scanner reads file bytes, then streams them to ClamAV in memory
- EICAR files should come back as `FOUND`, typically `Win.Test.EICAR_HDB-1`

Docker hardening already applied in `docker/Dockerfile`:
- **multi-stage build**: builder stage installs dependencies, runtime stage stays smaller
- **minimal base image**: `python:3.11-slim`
- **non-root runtime**: app runs as `appuser`, not root
- **reduced package footprint**: runtime only keeps `curl` for healthchecks
- **safer Python defaults**: `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`
- **healthcheck enabled**: FastAPI `/health` is used by Docker to verify readiness

Where ClamAV runs:
- ClamAV does **not** run inside the FastAPI image
- it runs as its **own container** using a pinned stable image: `clamav/clamav:1.5.2-debian13-slim`
- the FastAPI container connects to it over Docker Compose networking using:
  - `CLAMAV_HOST=clamav`
  - `CLAMAV_PORT=3310`

Why this pinned image choice:
- avoids floating `latest`
- stays on a newer stable 1.5.2 release line
- uses the slim Debian 13 variant to keep footprint lower
- is more predictable for enterprise-style environments than an unpinned mutable tag
Why I switched away from `*_base`:
- the full slim image is a better default for a ready-to-run ClamAV service
- it is safer for enterprise-style usage where you want fewer surprises from stripped-down runtime contents
- it still remains reasonably lightweight compared with larger full images
- for now I’m pinning the slimmer stable variant first so the deployment is explicit and reproducible

Important API note:
- the current FastAPI app does **not yet expose a local file upload endpoint** like `/scan/local`
- right now the API supports **S3 bucket scan operations**, not direct multipart file uploads
- for local ClamAV validation, the cleanest next step is to bring up the stack and verify:
  1. ClamAV container becomes healthy
  2. FastAPI `/health` responds
  3. then, if you want direct local file upload testing, I should add a new upload endpoint in a follow-up patch

Basic verification:
```bash
curl http://localhost:8000/health
```

## Full Setup (With AWS/Jira Optional)

### 1. Configure Environment

```bash
cp .env.example .env

# Edit .env and add your credentials:
# AWS_ACCESS_KEY_ID=your_key
# AWS_SECRET_ACCESS_KEY=your_secret
# AWS_REGION=us-east-1
# S3_BUCKET=your-bucket
# VIRUSTOTAL_API_KEY=your_key
# JIRA_URL=https://your-org.atlassian.net
# JIRA_API_TOKEN=your_token
```

### 2. Start the API Server

```bash
# Option A: Using uvicorn directly
python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Option B: Using Python
python src/main.py

# Server will start at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### 3. Test the API (in another terminal)

```bash
# Health check
curl http://localhost:8000/health

# Generate test data (requires S3 bucket)
curl -X POST "http://localhost:8000/generate-test-data" \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-bucket",
    "prefix": "test-data/",
    "dataset_size": "small"
  }'

# Start scan
curl -X POST "http://localhost:8000/scan/s3-bucket" \
  -H "Content-Type: application/json" \
  -d '{
    "bucket": "my-bucket",
    "prefix": "test-data/",
    "max_files": 100
  }'

# Get results
curl http://localhost:8000/results
```

## Project Structure

```
OpenSecOps-Analyzer/
├── src/                          # Source code
│   ├── main.py                   # FastAPI application
│   ├── config.py                 # Configuration
│   ├── scanner/                  # Scanning logic
│   ├── integrations/             # API integrations
│   ├── data_generation/          # Test data generation
│   ├── models/                   # Data models
│   └── utils/                    # Utilities
├── tests/                        # Unit tests
├── test_dataset/                 # Sample test data
│   ├── malware/                  # 10 EICAR test files
│   └── clean/                    # 10 clean files
├── docker/                       # Docker setup
├── requirements.txt              # Dependencies
├── test_local.py                 # Local testing script
├── README.md                     # Full documentation
├── QUICKSTART.md                 # Getting started
└── RUN_LOCALLY.md                # This file
```

## Test Dataset Details

Included in the project for immediate local testing:

- **test_dataset/malware/** - 10 EICAR test files (standard antivirus test pattern)
- **test_dataset/clean/** - 10 legitimate text files

Run without any configuration:
```bash
python test_local.py
```

Expected results:
- 21 total files scanned
- 11 detected as malware (EICAR files + README which contains "EICAR")
- 10 detected as clean
- 52.4% detection rate

## Troubleshooting

### Python Not Found
```bash
# Check Python version (need 3.8+)
python --version
python3 --version

# Use python3 explicitly
python3 -m venv venv
```

### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Docker Compose `.env` File Missing
```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

### ClamAV Container Takes Time to Become Healthy
```bash
# First startup may take longer while ClamAV initializes signatures
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs -f clamav
```

### Port Already in Use (8000)
```bash
# Use different port
python -m uvicorn src.main:app --port 8001

# Or kill process using port 8000
lsof -i :8000
kill -9 <PID>
```

### Permission Denied
```bash
# Make script executable
chmod +x test_local.py

# Run with python directly
python test_local.py
```

### AWS Credentials Error
```bash
# Test data doesn't require AWS
# To use S3 features, set credentials:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret

# Or configure AWS CLI
aws configure
```

## Performance Benchmarks

From included tests:

```
Local File Scanning (21 files):
- Duration: <1 second
- Throughput: 1000+ files/sec
- Memory: <100 MB

Performance Test (100k simulation):
- Duration: ~100 seconds
- Throughput: 1000 files/sec
- Memory: <500 MB peak
```

## File Structure After Extraction

```bash
OpenSecOps-Analyzer/
├── .env.example                  # Copy to .env
├── .gitignore                    # Git config
├── README.md                     # Main documentation
├── QUICKSTART.md                 # Quick start guide
├── RUN_LOCALLY.md                # This file
├── IMPLEMENTATION_SUMMARY.md     # Implementation details
├── requirements.txt              # Python packages
├── docker/
│   └── Dockerfile                # Docker image
├── src/
│   ├── main.py
│   ├── config.py
│   └── [modules...]
├── tests/
│   ├── test_scanner.py
│   ├── test_performance.py
│   └── [test files...]
└── test_dataset/
    ├── malware/
    │   └── [10 EICAR files]
    └── clean/
        └── [10 clean files]
```

## Next Steps

1. **Test Locally** (No AWS needed)
   ```bash
   python test_local.py
   ```

2. **Run Unit Tests**
   ```bash
   pytest tests/ -v
   ```

3. **Start API Server**
   ```bash
   python -m uvicorn src.main:app --reload
   ```

4. **Configure for S3** (Optional)
   - Edit .env with AWS credentials
   - Use API endpoints for S3 scanning

## Development Workflow

### Edit Code
```bash
# Virtual environment activated
source venv/bin/activate

# Edit any file in src/
vim src/scanner/hash_detector.py

# Test changes
python test_local.py
pytest tests/ -v
```

### Run with Auto-reload
```bash
python -m uvicorn src.main:app --reload
# Changes to src/ files will auto-reload
```

### Debug Logging
```bash
# Set debug level
export LOG_LEVEL=DEBUG
python test_local.py
```

## System Requirements

- **Python**: 3.8 or higher
- **RAM**: 512 MB minimum (1GB+ recommended)
- **Disk**: 500 MB for full install with dependencies
- **OS**: Linux, macOS, Windows (with WSL recommended)

## Dependencies Installed

See `requirements.txt` for complete list:
- fastapi, uvicorn - Web framework
- boto3 - AWS S3
- requests - HTTP client
- pydantic - Data validation
- psutil - System metrics
- pytest - Testing

## Support

For issues:
1. Check test output for detailed error messages
2. Review logs with `LOG_LEVEL=DEBUG`
3. See README.md for architecture details
4. Check QUICKSTART.md for examples

## Quick Reference

```bash
# Extract
unzip OpenSecOps-Analyzer.zip && cd OpenSecOps-Analyzer

# Install
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Test locally
python test_local.py

# Run tests
pytest tests/ -v

# Start server
python -m uvicorn src.main:app --reload

# Access API
# Browser: http://localhost:8000/docs
# Terminal: curl http://localhost:8000/health
```

That's it! The project is ready to run locally with no configuration needed for basic testing.
