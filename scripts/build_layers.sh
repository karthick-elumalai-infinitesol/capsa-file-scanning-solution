#!/usr/bin/env bash
# Build Lambda deployment packages with dependencies
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/infrastructure"
LAYERS_DIR="${INFRA_DIR}/lambda_layers"

build_layer() {
    local layer_name="$1"
    local requirements_file="$2"
    local output_dir="${LAYERS_DIR}/${layer_name}"

    echo "Building layer: ${layer_name}"
    rm -rf "${output_dir}"
    mkdir -p "${output_dir}/python"

    pip install \
        --quiet \
        --no-cache-dir \
        -r "${requirements_file}" \
        --target "${output_dir}/python"

    cd "${output_dir}"
    zip -qr "${layer_name}.zip" python/
    echo "  → ${output_dir}/${layer_name}.zip"
}

# Build shared redis-py layer for scan_trigger Lambda
build_layer "capsa-redis-layer" "${SCRIPT_DIR}/lambda_functions/scan_trigger/requirements.txt"

echo "All Lambda layers built successfully."
