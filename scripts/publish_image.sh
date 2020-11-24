#!/usr/bin/env bash

set -e
set -x

CONTAINER_NAME=$1

: "${VERSION?Need to set VERSION}"
: "${BRANCH?Need to set BRANCH}"

REPO_NAME=skalenetwork/$CONTAINER_NAME
IMAGE_NAME=$REPO_NAME:$VERSION

LATEST_IMAGE_NAME=$REPO_NAME:$BRANCH-latest
docker tag "${IMAGE_NAME}" "${LATEST_IMAGE_NAME}"

: "${DOCKER_USERNAME?Need to set DOCKER_USERNAME}"
: "${DOCKER_PASSWORD?Need to set DOCKER_PASSWORD}"

echo "$DOCKER_PASSWORD" | docker login --username "$DOCKER_USERNAME" --password-stdin

docker push "$IMAGE_NAME" || exit $?
docker push "$LATEST_IMAGE_NAME" || exit $?
