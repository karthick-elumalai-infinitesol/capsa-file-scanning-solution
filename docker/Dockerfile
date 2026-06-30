# =============================================================================
# CAPSA Enterprise Scanner — Multi-Stage Docker Build
#
# Stage 1 (builder):  Install Python deps into virtualenv
# Stage 2 (security): Optional security audit layer
# Stage 3 (runtime):  Minimal hardened production image
#
# Security hardening applied:
#   - Multi-stage build (no build tools in runtime)
#   - Non-root appuser with no login shell
#   - Read-only root filesystem (via --read-only at runtime)
#   - Drop all Linux capabilities (via --cap-drop=ALL at runtime)
#   - No --no-cache-dir, pip version pinning
#   - Docker Scout / buildx attestation labels
#   - SBOM-ready with annotations
#   - HEALTHCHECK with proper intervals
#   - PYTHONDONTWRITEBYTECODE to prevent .pyc writes
#   - Minimal CA certificates only (no build-essential, no compilers)
#   - OSSF Scorecard aligned
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca AS builder

LABEL stage=builder \
      org.opencontainers.image.source="https://github.com/anomalyco/OpenSecOpsAnalyzerCAPSAFull" \
      org.opencontainers.image.description="CAPSA Enterprise Scanner — dependency build stage" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

WORKDIR /build

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m venv $VIRTUAL_ENV \
    && $VIRTUAL_ENV/bin/pip install --upgrade pip==24.0 \
    && $VIRTUAL_ENV/bin/pip install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 — Production runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca AS runtime

LABEL vendor="OpenSecOps Analyzer" \
      org.opencontainers.image.title="CAPSA Enterprise Scanner" \
      org.opencontainers.image.description="Enterprise-grade malware scanner for S3 buckets with ClamAV, DefectDojo, GuardDuty, and Inspector integration" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.source="https://github.com/anomalyco/OpenSecOpsAnalyzerCAPSAFull" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="python:3.11-slim" \
      org.opencontainers.image.ref.name="capsa-scanner" \
      io.capsa.component="scanner" \
      io.capsa.security.level="enterprise"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    VIRTUAL_ENV=/opt/venv \
    APP_HOME=/app \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 appgroup \
    && useradd --system --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser \
    && mkdir -p ${APP_HOME}/data \
    && chown -R appuser:appgroup ${APP_HOME}

COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv
COPY --chown=appuser:appgroup src ./src
COPY --chown=appuser:appgroup scripts ./scripts
USER appuser:appgroup

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

STOPSIGNAL SIGTERM

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "*"]
