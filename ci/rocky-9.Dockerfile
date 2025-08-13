ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}rockylinux:9

LABEL org.opencontainers.image.source=https://github.com/NationalSecurityAgency/seabee

COPY scripts /scripts

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# update the path for rust installation
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH
