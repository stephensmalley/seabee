ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}rust:1.79.0-slim

COPY scripts/update_root_dependencies.sh /scripts/update_root_dependencies.sh
COPY scripts/update_test_dependencies.sh /scripts/update_test_dependencies.sh
COPY scripts/update_dependencies.sh /scripts/update_dependencies.sh

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && rm -rf /var/lib/apt/lists/*
