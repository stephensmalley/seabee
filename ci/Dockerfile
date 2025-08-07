ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}rust:slim

LABEL org.opencontainers.image.source=https://github.com/NationalSecurityAgency/seabee

COPY scripts /scripts

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && rm -rf /var/lib/apt/lists/*
