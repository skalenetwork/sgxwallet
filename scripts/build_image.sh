#!/usr/bin/env bash

set -e
set -x

DOCKERFILE=$1
CONTAINER_NAME=$2

# Unpublished builds (pull requests, local runs) are tagged with the commit SHA
VERSION=${VERSION-$(git rev-parse HEAD)}
BRANCH=${BRANCH-local}

REPO_NAME=skalenetwork/$CONTAINER_NAME
IMAGE_NAME=$REPO_NAME:$VERSION

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Build image

echo "Building $IMAGE_NAME..."
docker build -f "${DIR}"/../"${DOCKERFILE}" -t "${IMAGE_NAME}" . || exit $?

if [ "${BRANCH}" = "stable" ];
then
	LATEST_IMAGE_NAME=$REPO_NAME:latest
	docker tag "${IMAGE_NAME}" "${LATEST_IMAGE_NAME}"
else
	LATEST_IMAGE_NAME=$REPO_NAME:$BRANCH-latest
	docker tag "${IMAGE_NAME}" "${LATEST_IMAGE_NAME}"
fi

echo "========================================================================================="
echo "Built $IMAGE_NAME"