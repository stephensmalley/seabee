#!/bin/bash

TOP_DIR=$(dirname "$(dirname "$(realpath "$0" || true)")")

source "$TOP_DIR"/ci/.env || true

# docker context use rootless
docker run \
  --rm \
  -v "$TOP_DIR":/tmp/lint:rw \
  ${DOCKER_MIRROR}oxsecurity/megalinter:v7.12.0
# docker context use default
