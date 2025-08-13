ARG DOCKER_MIRROR

FROM ${DOCKER_MIRROR}fedora:42

LABEL org.opencontainers.image.source=https://github.com/NationalSecurityAgency/seabee

COPY scripts /scripts

# fedora image does not include python, python not added by update_dependencies.sh
RUN dnf -y install python3

RUN DOCKER=1 /scripts/update_dependencies.sh \
    && dnf clean all

# update the path for rust installation
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH
