#!/usr/bin/env bash

set -e

DOCKERFILE=$1

: "${VERSION?Need to set VERSION}"
: "${BRANCH?Need to set BRANCH}"

NAME=sgx
REPO_NAME=skalenetwork/$NAME
IMAGE_NAME=$REPO_NAME:$VERSION
LATEST_IMAGE_NAME=$REPO_NAME:$BRANCH-latest

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Build image

echo "Building $IMAGE_NAME..."
docker build -f "${DIR}"/../"${DOCKERFILE}" -t "${IMAGE_NAME}" . || exit $?
docker tag "${IMAGE_NAME}" "${LATEST_IMAGE_NAME}"

echo "========================================================================================="
echo "Built $IMAGE_NAME"