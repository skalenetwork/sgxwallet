#!/usr/bin/env bash
set -euo pipefail

############################################
##     Setup paths and environment
############################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

source /opt/intel/sgxsdk/environment

VALIDATOR="${SCRIPT_DIR}/api_validator"
VECTORS="${SCRIPT_DIR}/api_golden_vectors.json"
SERVER_LOG="${ROOT_DIR}/sgx_data/sgxwallet.log"

# check api_golden_vectors.json exists
if [[ ! -f "${VECTORS}" ]]; then
  echo "Missing golden vectors: ${VECTORS}" >&2
  exit 1
fi

# check sgxwallet binary exists
if [[ ! -x "${ROOT_DIR}/sgxwallet" ]]; then
  echo "sgxwallet binary not found at ${ROOT_DIR}/sgxwallet" >&2
  exit 1
fi

############################################
##     Setup cleanup on exit
############################################

# define & register cleanup function to run on script exit
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi

  # sgx_data is often a bind-mount in CI; remove contents, not the mountpoint dir.
  if [[ -d "${ROOT_DIR}/sgx_data" ]]; then
    find "${ROOT_DIR}/sgx_data" -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
  fi

  # optional: only clean if you really want this every run
  make -C "${SCRIPT_DIR}" clean || true
}
trap cleanup EXIT INT TERM

############################################
##     Build test
############################################

# build api_validator using SCRIPT_DIR as working directory
make -C "${SCRIPT_DIR}" api_validator

# start with a clean sgx_data directory
mkdir -p "${ROOT_DIR}/sgx_data"
# clean everything inside
find "${ROOT_DIR}/sgx_data" -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true

############################################
##     Start sgxwallet & wait for it
############################################

mkdir -p "${ROOT_DIR}/sgx_data"

pushd "${ROOT_DIR}" >/dev/null
./sgxwallet -n -s -y -d -V > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
popd >/dev/null


ready=false
for _ in $(seq 1 30); do

  # check if process is healthy & running
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "sgxwallet exited before readiness; see ${SERVER_LOG}" >&2
    exit 1
  fi

  # check if sgxwallet is ready to accept requests
  if curl -s -X POST -H 'content-type:application/json' \
      --data '{"jsonrpc":"2.0","method":"getServerVersion","params":[],"id":1}' \
      http://localhost:1029 >/dev/null; then
    ready=true
    break
  fi

  # wait a bit before retrying
  sleep 1
done

if [[ "${ready}" != "true" ]]; then
  echo "sgxwallet did not become ready; see ${SERVER_LOG}" >&2
  exit 1
fi

############################################
##     Run backward compatibility test
############################################

"${VALIDATOR}" "${VECTORS}"
