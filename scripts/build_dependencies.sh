#!/bin/bash

set -e

# Allow override via PARALLEL_COUNT env var or CLI arg PARALLEL_COUNT=N.
PARALLEL_COUNT="${PARALLEL_COUNT:-$(nproc)}"
for arg in "$@"; do
    case "$arg" in
        PARALLEL_COUNT=*)
            PARALLEL_COUNT="${arg#PARALLEL_COUNT=}"
            ;;
    esac
done

./build_deps.py "PARALLEL_COUNT=${PARALLEL_COUNT}"