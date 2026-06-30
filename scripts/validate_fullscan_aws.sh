#!/usr/bin/env bash
# CAPSA AWS fullscan validator
#
# Validates the deployed AWS file-scanning pipeline with a batch of clean files
# and EICAR malware test files:
#   S3 staging -> scan_trigger Lambda -> Redis/ECS worker -> ClamAV -> routing Lambda
#   -> clean bucket OR quarantine bucket.
#
# Safe cleanup behavior:
#   - Removes validation files from staging and clean buckets.
#   - Keeps quarantine objects by default for audit/review evidence.

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
FILE_COUNT="${FILE_COUNT:-10}"
WAIT_SECONDS="${WAIT_SECONDS:-120}"
CLEANUP="${CLEANUP:-true}"
CLEANUP_QUARANTINE="${CLEANUP_QUARANTINE:-false}"
AWS_PAGER="${AWS_PAGER:-}"
export AWS_REGION AWS_PAGER

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="$PROJECT_ROOT/infrastructure"

info() { printf '\n\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

tf_output() {
  (cd "$INFRA_DIR" && terraform output -raw "$1")
}

count_s3_objects() {
  local bucket="$1"
  local prefix="$2"
  aws s3 ls "s3://$bucket/$prefix" --recursive --region "$AWS_REGION" | wc -l | tr -d '[:space:]'
}

sum_numeric_output() {
  awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) total += $i } END { print total + 0 }'
}

require_cmd aws
require_cmd terraform

info "Loading Terraform outputs"
STAGING_BUCKET="$(tf_output staging_bucket)"
CLEAN_BUCKET="$(tf_output clean_bucket)"
QUARANTINE_BUCKET="$(tf_output quarantine_bucket)"
SCAN_TRIGGER="$(tf_output scan_trigger_function_name)"
ROUTING_ENGINE="$(tf_output routing_engine_function_name)"
CLUSTER_NAME="$(tf_output ecs_cluster_name)"
TEST_PREFIX="fullscan-validation-$(date +%Y%m%d%H%M%S)"
WORK_DIR="/tmp/capsa-fullscan-$TEST_PREFIX"

info "Test prefix: $TEST_PREFIX"
info "Region: $AWS_REGION"
info "Staging bucket: $STAGING_BUCKET"
info "Clean bucket: $CLEAN_BUCKET"
info "Quarantine bucket: $QUARANTINE_BUCKET"

info "Checking AWS identity"
aws sts get-caller-identity --region "$AWS_REGION" --output table >/dev/null
ok "AWS credentials are valid"

info "Checking ECS services"
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
ok "ECS services are stable"

info "Generating $FILE_COUNT clean files and $FILE_COUNT EICAR files"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/clean" "$WORK_DIR/malware"

for i in $(seq 1 "$FILE_COUNT"); do
  echo "CAPSA clean validation file $i generated at $(date -u)" > "$WORK_DIR/clean/clean-$i.txt"
done

for i in $(seq 1 "$FILE_COUNT"); do
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK_DIR/malware/eicar-$i.com"
done

EICAR_SIZE="$(wc -c < "$WORK_DIR/malware/eicar-1.com" | tr -d '[:space:]')"
[[ "$EICAR_SIZE" == "68" ]] || fail "Invalid EICAR size: expected 68, got $EICAR_SIZE"
ok "Generated valid EICAR files"

info "Uploading validation batch to staging"
aws s3 cp "$WORK_DIR/clean/" "s3://$STAGING_BUCKET/$TEST_PREFIX/clean/" --recursive --region "$AWS_REGION"
aws s3 cp "$WORK_DIR/malware/" "s3://$STAGING_BUCKET/$TEST_PREFIX/malware/" --recursive --region "$AWS_REGION"
ok "Uploaded $(( FILE_COUNT * 2 )) files to staging"

info "Waiting $WAIT_SECONDS seconds for scan/routing"
sleep "$WAIT_SECONDS"

info "Counting scan results"
STAGING_COUNT="$(count_s3_objects "$STAGING_BUCKET" "$TEST_PREFIX/")"
CLEAN_COUNT="$(count_s3_objects "$CLEAN_BUCKET" "$TEST_PREFIX/clean/")"
QUARANTINE_COUNT="$(count_s3_objects "$QUARANTINE_BUCKET" "$TEST_PREFIX/malware/")"

printf '\n%-22s %s\n' "staging_count" "$STAGING_COUNT"
printf '%-22s %s\n' "clean_count" "$CLEAN_COUNT"
printf '%-22s %s\n' "quarantine_count" "$QUARANTINE_COUNT"

[[ "$CLEAN_COUNT" == "$FILE_COUNT" ]] || fail "Expected $FILE_COUNT clean files, found $CLEAN_COUNT"
[[ "$QUARANTINE_COUNT" == "$FILE_COUNT" ]] || fail "Expected $FILE_COUNT quarantined malware files, found $QUARANTINE_COUNT"
ok "Routing counts are correct"

info "Validating quarantine tags and metadata"
TAG_STATUS="$(aws s3api get-object-tagging \
  --region "$AWS_REGION" \
  --bucket "$QUARANTINE_BUCKET" \
  --key "$TEST_PREFIX/malware/eicar-1.com" \
  --query 'TagSet[?Key==`scan:status`].Value | [0]' \
  --output text)"
TAG_ENGINE="$(aws s3api get-object-tagging \
  --region "$AWS_REGION" \
  --bucket "$QUARANTINE_BUCKET" \
  --key "$TEST_PREFIX/malware/eicar-1.com" \
  --query 'TagSet[?Key==`scan:engine`].Value | [0]' \
  --output text)"
OBJECT_SIZE="$(aws s3api head-object \
  --region "$AWS_REGION" \
  --bucket "$QUARANTINE_BUCKET" \
  --key "$TEST_PREFIX/malware/eicar-1.com" \
  --query 'ContentLength' \
  --output text)"

[[ "$TAG_STATUS" == "INFECTED" ]] || fail "Expected scan:status=INFECTED, got $TAG_STATUS"
[[ "$TAG_ENGINE" == "clamav" ]] || fail "Expected scan:engine=clamav, got $TAG_ENGINE"
[[ "$OBJECT_SIZE" == "68" ]] || fail "Expected quarantined object size 68, got $OBJECT_SIZE"
ok "Quarantine tags and metadata are correct"

START_TIME_MS="$(( ($(date +%s) - 1800) * 1000 ))"

info "Checking Lambda and ECS logs for fresh errors"
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
ok "No fresh Lambda/ECS error logs found"

if [[ "$CLEANUP" == "true" ]]; then
  info "Cleaning staging and clean validation files"
  aws s3 rm "s3://$STAGING_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
  aws s3 rm "s3://$CLEAN_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
  ok "Cleaned staging and clean validation files"
fi

if [[ "$CLEANUP_QUARANTINE" == "true" ]]; then
  info "Cleaning quarantine validation files because CLEANUP_QUARANTINE=true"
  aws s3 rm "s3://$QUARANTINE_BUCKET/$TEST_PREFIX/" --recursive --region "$AWS_REGION"
  ok "Cleaned quarantine validation files"
else
  info "Quarantine validation files retained for audit/review: s3://$QUARANTINE_BUCKET/$TEST_PREFIX/"
fi

rm -rf "$WORK_DIR"

ok "Fullscan validation PASSED"
printf '\nSummary:\n'
printf '  Prefix:              %s\n' "$TEST_PREFIX"
printf '  Clean files routed:  %s/%s\n' "$CLEAN_COUNT" "$FILE_COUNT"
printf '  Malware quarantined: %s/%s\n' "$QUARANTINE_COUNT" "$FILE_COUNT"
printf '  scan:status:         %s\n' "$TAG_STATUS"
printf '  scan:engine:         %s\n' "$TAG_ENGINE"
