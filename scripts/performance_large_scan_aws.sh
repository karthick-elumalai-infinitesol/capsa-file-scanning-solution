#!/usr/bin/env bash
# CAPSA AWS large-file performance validator
#
# Creates configurable large clean files and large EICAR-containing malware files,
# uploads them to the staging bucket, waits for routing, and reports end-to-end
# scan/routing throughput.

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
FILE_COUNT="${FILE_COUNT:-3}"
FILE_SIZE_MB="${FILE_SIZE_MB:-50}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-900}"
POLL_SECONDS="${POLL_SECONDS:-15}"
CLEANUP="${CLEANUP:-true}"
CLEANUP_QUARANTINE="${CLEANUP_QUARANTINE:-false}"
AWS_PAGER="${AWS_PAGER:-}"
export AWS_REGION AWS_PAGER

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="$PROJECT_ROOT/infrastructure"

info() { printf '\n\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }
tf_output() { (cd "$INFRA_DIR" && terraform output -raw "$1"); }

count_s3_objects() {
  local bucket="$1"
  local prefix="$2"
  aws s3 ls "s3://$bucket/$prefix" --recursive --region "$AWS_REGION" | wc -l | tr -d '[:space:]'
}

sum_s3_bytes() {
  local bucket="$1"
  local prefix="$2"
  aws s3 ls "s3://$bucket/$prefix" --recursive --region "$AWS_REGION" \
    | awk '{ total += $3 } END { print total + 0 }'
}

sum_numeric_output() {
  awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) total += $i } END { print total + 0 }'
}

bytes_to_mib() {
  awk -v bytes="$1" 'BEGIN { printf "%.2f", bytes / 1024 / 1024 }'
}

throughput_mib_s() {
  awk -v bytes="$1" -v seconds="$2" 'BEGIN { if (seconds <= 0) seconds = 1; printf "%.2f", (bytes / 1024 / 1024) / seconds }'
}

require_cmd aws
require_cmd terraform
require_cmd python3

info "Loading Terraform outputs"
STAGING_BUCKET="$(tf_output staging_bucket)"
CLEAN_BUCKET="$(tf_output clean_bucket)"
QUARANTINE_BUCKET="$(tf_output quarantine_bucket)"
SCAN_TRIGGER="$(tf_output scan_trigger_function_name)"
ROUTING_ENGINE="$(tf_output routing_engine_function_name)"
CLUSTER_NAME="$(tf_output ecs_cluster_name)"
TEST_PREFIX="large-perf-validation-$(date +%Y%m%d%H%M%S)"
WORK_DIR="/tmp/capsa-large-perf-$TEST_PREFIX"
EXPECTED_TOTAL_FILES="$(( FILE_COUNT * 2 ))"
EXPECTED_TOTAL_BYTES="$(( EXPECTED_TOTAL_FILES * FILE_SIZE_MB * 1024 * 1024 ))"

info "Configuration"
printf '  Region:              %s\n' "$AWS_REGION"
printf '  Prefix:              %s\n' "$TEST_PREFIX"
printf '  File count/type:     %s\n' "$FILE_COUNT"
printf '  File size:           %s MiB\n' "$FILE_SIZE_MB"
printf '  Total test data:     %s MiB\n' "$(bytes_to_mib "$EXPECTED_TOTAL_BYTES")"
printf '  Wait timeout:        %s seconds\n' "$WAIT_TIMEOUT_SECONDS"

info "Checking AWS identity and ECS health"
aws sts get-caller-identity --region "$AWS_REGION" --output table >/dev/null
aws ecs describe-services \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --services capsa-prod-redis-service capsa-prod-queue-worker-service capsa-prod-clamav-service \
  --query 'services[].{name:serviceName,status:status,desired:desiredCount,running:runningCount,pending:pendingCount,rollout:deployments[0].rolloutState}' \
  --output table

UNHEALTHY_COUNT="$(aws ecs describe-services \
  --region "$AWS_REGION" \
  --cluster "$CLUSTER_NAME" \
  --services capsa-prod-redis-service capsa-prod-queue-worker-service capsa-prod-clamav-service \
  --query 'length(services[?runningCount!=desiredCount || pendingCount!=`0`])' \
  --output text)"
[[ "$UNHEALTHY_COUNT" == "0" ]] || fail "One or more ECS services are not stable"
ok "AWS credentials and ECS services are healthy"

info "Generating large local test files in $WORK_DIR"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/clean" "$WORK_DIR/malware"

export FILE_COUNT FILE_SIZE_MB WORK_DIR
python3 - <<'PY'
import os
from pathlib import Path

file_count = int(os.environ["FILE_COUNT"])
file_size = int(os.environ["FILE_SIZE_MB"]) * 1024 * 1024
work_dir = Path(os.environ["WORK_DIR"])
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

for i in range(1, file_count + 1):
    clean_path = work_dir / "clean" / f"large-clean-{i}.bin"
    malware_path = work_dir / "malware" / f"large-eicar-{i}.bin"

    with clean_path.open("wb") as fh:
        header = f"CAPSA clean large performance file {i}\n".encode()
        fh.write(header)
        remaining = file_size - len(header)
        chunk = (b"CLEAN-DATA-%06d\n" % i) * 4096
        while remaining > 0:
            data = chunk[:min(len(chunk), remaining)]
            fh.write(data)
            remaining -= len(data)

    with malware_path.open("wb") as fh:
        # Put EICAR at the beginning, then pad to large size. This validates
        # that the scanner reads and scans the full uploaded object path while
        # still producing a deterministic ClamAV detection.
        fh.write(eicar)
        remaining = file_size - len(eicar)
        chunk = (b"-PADDING-FOR-LARGE-EICAR-PERFORMANCE-TEST-" * 2048)
        while remaining > 0:
            data = chunk[:min(len(chunk), remaining)]
            fh.write(data)
            remaining -= len(data)
PY

LOCAL_BYTES="$(find "$WORK_DIR" -type f -print0 | xargs -0 stat -f '%z' | awk '{ total += $1 } END { print total + 0 }')"
ok "Generated $(find "$WORK_DIR" -type f | wc -l | tr -d '[:space:]') files ($(bytes_to_mib "$LOCAL_BYTES") MiB)"

info "Uploading files to staging and measuring upload time"
UPLOAD_START="$(date +%s)"
aws s3 cp "$WORK_DIR/clean/" "s3://$STAGING_BUCKET/$TEST_PREFIX/clean/" --recursive --region "$AWS_REGION"
aws s3 cp "$WORK_DIR/malware/" "s3://$STAGING_BUCKET/$TEST_PREFIX/malware/" --recursive --region "$AWS_REGION"
UPLOAD_END="$(date +%s)"
UPLOAD_SECONDS="$(( UPLOAD_END - UPLOAD_START ))"
ok "Upload completed in ${UPLOAD_SECONDS}s ($(throughput_mib_s "$LOCAL_BYTES" "$UPLOAD_SECONDS") MiB/s)"

info "Polling for routing completion"
SCAN_START="$UPLOAD_END"
DEADLINE="$(( SCAN_START + WAIT_TIMEOUT_SECONDS ))"
CLEAN_COUNT=0
QUARANTINE_COUNT=0

while true; do
  CLEAN_COUNT="$(count_s3_objects "$CLEAN_BUCKET" "$TEST_PREFIX/clean/")"
  QUARANTINE_COUNT="$(count_s3_objects "$QUARANTINE_BUCKET" "$TEST_PREFIX/malware/")"
  NOW="$(date +%s)"
  ELAPSED="$(( NOW - SCAN_START ))"
  printf '  elapsed=%ss clean=%s/%s quarantine=%s/%s\n' "$ELAPSED" "$CLEAN_COUNT" "$FILE_COUNT" "$QUARANTINE_COUNT" "$FILE_COUNT"

  if [[ "$CLEAN_COUNT" == "$FILE_COUNT" && "$QUARANTINE_COUNT" == "$FILE_COUNT" ]]; then
    break
  fi

  if (( NOW >= DEADLINE )); then
    fail "Timed out waiting for routing completion"
  fi

  sleep "$POLL_SECONDS"
done

SCAN_END="$(date +%s)"
SCAN_SECONDS="$(( SCAN_END - SCAN_START ))"
CLEAN_BYTES="$(sum_s3_bytes "$CLEAN_BUCKET" "$TEST_PREFIX/clean/")"
QUARANTINE_BYTES="$(sum_s3_bytes "$QUARANTINE_BUCKET" "$TEST_PREFIX/malware/")"
ROUTED_BYTES="$(( CLEAN_BYTES + QUARANTINE_BYTES ))"
FILES_PER_SECOND="$(awk -v files="$EXPECTED_TOTAL_FILES" -v seconds="$SCAN_SECONDS" 'BEGIN { if (seconds <= 0) seconds = 1; printf "%.2f", files / seconds }')"

ok "Routing completed"

info "Validating quarantine detection tags"
TAG_STATUS="$(aws s3api get-object-tagging \
  --region "$AWS_REGION" \
  --bucket "$QUARANTINE_BUCKET" \
  --key "$TEST_PREFIX/malware/large-eicar-1.bin" \
  --query 'TagSet[?Key==`scan:status`].Value | [0]' \
  --output text)"
TAG_ENGINE="$(aws s3api get-object-tagging \
  --region "$AWS_REGION" \
  --bucket "$QUARANTINE_BUCKET" \
  --key "$TEST_PREFIX/malware/large-eicar-1.bin" \
  --query 'TagSet[?Key==`scan:engine`].Value | [0]' \
  --output text)"

[[ "$TAG_STATUS" == "INFECTED" ]] || fail "Expected scan:status=INFECTED, got $TAG_STATUS"
[[ "$TAG_ENGINE" == "clamav" ]] || fail "Expected scan:engine=clamav, got $TAG_ENGINE"
ok "Large malware file detected as INFECTED by ClamAV"

START_TIME_MS="$(( (UPLOAD_START - 300) * 1000 ))"
info "Checking fresh error logs"
SCAN_ERRORS="$(aws logs filter-log-events \
  --region "$AWS_REGION" \
  --log-group-name "/aws/lambda/$SCAN_TRIGGER" \
  --start-time "$START_TIME_MS" \
  --filter-pattern "ERROR" \
  --query 'length(events)' \
  --output text | sum_numeric_output)"
ROUTING_ERRORS="$(aws logs filter-log-events \
  --region "$AWS_REGION" \
  --log-group-name "/aws/lambda/$ROUTING_ENGINE" \
  --start-time "$START_TIME_MS" \
  --filter-pattern "ERROR" \
  --query 'length(events)' \
  --output text | sum_numeric_output)"
REDIS_TIMEOUTS="$(aws logs filter-log-events \
  --region "$AWS_REGION" \
  --log-group-name /ecs/capsa-prod-queue-worker \
  --start-time "$START_TIME_MS" \
  --filter-pattern 'Redis dequeue failed' \
  --query 'length(events)' \
  --output text | sum_numeric_output)"

[[ "$SCAN_ERRORS" == "0" ]] || fail "Found $SCAN_ERRORS scan-trigger Lambda ERROR logs"
[[ "$ROUTING_ERRORS" == "0" ]] || fail "Found $ROUTING_ERRORS routing-engine Lambda ERROR logs"
[[ "$REDIS_TIMEOUTS" == "0" ]] || fail "Found $REDIS_TIMEOUTS Redis dequeue timeout errors"
ok "No fresh error logs found"

if [[ "$CLEANUP" == "true" ]]; then
  info "Cleaning staging and clean validation files"
  aws s3 rm "s3://$STAGING_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
  aws s3 rm "s3://$CLEAN_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
  ok "Cleaned staging and clean validation files"
fi

if [[ "$CLEANUP_QUARANTINE" == "true" ]]; then
  warn "Cleaning quarantine validation files because CLEANUP_QUARANTINE=true"
  aws s3 rm "s3://$QUARANTINE_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
else
  info "Quarantine validation files retained: s3://$QUARANTINE_BUCKET/$TEST_PREFIX/"
fi

rm -rf "$WORK_DIR"

printf '\n========== LARGE FILE PERFORMANCE SUMMARY =========='"\n"
printf 'Prefix:                  %s\n' "$TEST_PREFIX"
printf 'Files tested:            %s clean + %s malware = %s total\n' "$FILE_COUNT" "$FILE_COUNT" "$EXPECTED_TOTAL_FILES"
printf 'File size:               %s MiB each\n' "$FILE_SIZE_MB"
printf 'Uploaded bytes:          %s MiB\n' "$(bytes_to_mib "$LOCAL_BYTES")"
printf 'Routed bytes:            %s MiB\n' "$(bytes_to_mib "$ROUTED_BYTES")"
printf 'Upload duration:         %s seconds\n' "$UPLOAD_SECONDS"
printf 'Upload throughput:       %s MiB/s\n' "$(throughput_mib_s "$LOCAL_BYTES" "$UPLOAD_SECONDS")"
printf 'Scan/routing duration:   %s seconds\n' "$SCAN_SECONDS"
printf 'Scan/routing throughput: %s MiB/s\n' "$(throughput_mib_s "$ROUTED_BYTES" "$SCAN_SECONDS")"
printf 'File throughput:         %s files/s\n' "$FILES_PER_SECOND"
printf 'Clean routed:            %s/%s\n' "$CLEAN_COUNT" "$FILE_COUNT"
printf 'Malware quarantined:     %s/%s\n' "$QUARANTINE_COUNT" "$FILE_COUNT"
printf 'Detection status:        %s via %s\n' "$TAG_STATUS" "$TAG_ENGINE"
printf '====================================================\n'

ok "Large-file performance validation PASSED"
