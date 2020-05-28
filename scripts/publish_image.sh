#!/usr/bin/env bash

set -e

CONTAINER_NAME=$1

: "${VERSION?Need to set VERSION}"
: "${BRANCH?Need to set BRANCH}"

NAME=sgx
REPO_NAME=skalenetwork/$NAME
IMAGE_NAME=$REPO_NAME.$CONTAINER_NAME:$VERSION
LATEST_IMAGE_NAME=$REPO_NAME:$BRANCH-latest

: "${DOCKER_USERNAME?Need to set DOCKER_USERNAME}"
: "${DOCKER_PASSWORD?Need to set DOCKER_PASSWORD}"

echo "$DOCKER_PASSWORD" | docker login --username "$DOCKER_USERNAME" --password-stdin

docker push "$IMAGE_NAME" || exit $?
docker push "$LATEST_IMAGE_NAME" || exit $?
