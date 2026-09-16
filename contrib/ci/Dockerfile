# Container image for running the test suite.
#
# Interim: this image is to be replaced by one built from the repository's
# Nix flake, and this file removed when that lands.
#
# Bakes everything ci.yaml installs at job time via .github/scripts/setup.sh
# plus a pre-warmed uv venv and cargo registry, so a test run needs no apt
# installs and no network fetches. It is a root image: the checkout is made
# as root, and the test suite drops privilege to `tester` (below) when it
# runs.
#
# This is a CI image, not a sandbox. `tester` has passwordless sudo and git's
# ownership check is disabled image-wide, so anything you run in it runs with
# your privileges -- fine for a throwaway CI container, worth knowing before
# you mount your working tree into one.
#
# To reproduce a CI failure locally, build it from the repository root:
#
#     docker build -t cln-ci -f contrib/ci/Dockerfile .
ARG BASE_REGISTRY=docker.io/library
FROM ${BASE_REGISTRY}/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUST_VERSION=stable \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/bitcoin/bin:/opt/elements/bin:$PATH \
    UV_PROJECT_ENVIRONMENT=/opt/cln-venv \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    CARGO_INCREMENTAL=0

# Same apt list as .github/scripts/setup.sh, minus the eatmydata bootstrap
# dance (not needed for a one-shot image build) and the arm/aarch64 cross
# toolchains needed for compile-32bit (those belong in a separate 32-bit
# image).
# Plus libclang-rt-18-dev: clang only Recommends its compiler-rt runtime, so
# --no-install-recommends drops the ASan/UBSan libraries that GitHub's runner
# image happens to preinstall.
# ubuntu:24.04 is a minimized image: dpkg drops man pages and /usr/bin/man is
# a stub printing "This system has been minimized", which `lightning-cli help`
# (test_cli_multiline_help) shows instead of the page. Undo both before
# installing man-db.
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && \
    if [ "$(dpkg-divert --truename /usr/bin/man)" = "/usr/bin/man.REAL" ]; then \
        rm -f /usr/bin/man && dpkg-divert --quiet --remove --rename /usr/bin/man; \
    fi

RUN apt-get update && \
    apt-get install --no-install-recommends -yy \
        autoconf \
        automake \
        binfmt-support \
        build-essential \
        ca-certificates \
        clang \
        libclang-rt-18-dev \
        cppcheck \
        curl \
        docbook-xml \
        eatmydata \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabihf \
        gcc-arm-none-eabi \
        gettext \
        git \
        gnupg \
        jq \
        libc6-dev-arm64-cross \
        libc6-dev-armhf-cross \
        libev-dev \
        libevent-dev \
        libffi-dev \
        libicu-dev \
        libpq-dev \
        libprotobuf-c-dev \
        libsodium-dev \
        libsqlite3-dev \
        libssl-dev \
        pkg-config \
        libtool \
        libxml2-utils \
        locales \
        lowdown \
        man-db \
        net-tools \
        postgresql \
        python3 \
        python3-dev \
        qemu-system \
        qemu-system-arm \
        qemu-user-static \
        shellcheck \
        sudo \
        tcl \
        tclsh \
        tshark \
        unzip \
        valgrind \
        wget \
        wireshark-common \
        xsltproc \
        systemtap-sdt-dev \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# wireshark-common's postinst does this on a real install; do it explicitly
# since the package's maintainer scripts don't run the same way in a
# from-scratch image build.
RUN groupadd -f wireshark && \
    chgrp wireshark /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# The checkout may be owned by a uid other than the one running git, which
# trips git's safe.directory check and breaks `git describe` (VERSION in
# Makefile). System-wide, so it applies to root and tester alike.
RUN git config --system --add safe.directory '*'

# tester: uid 1000, the identity the test suite runs under. postgres refuses
# to initdb as root, and dumpcap needs the wireshark group.
# ubuntu:24.04 ships its own uid-1000 "ubuntu" user; drop it first.
RUN (userdel -r ubuntu 2>/dev/null || true) && \
    useradd -m -u 1000 -G wireshark -s /bin/bash tester && \
    echo "tester ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/tester && \
    chmod 0440 /etc/sudoers.d/tester

# --retry: don't fail the whole image build on a transient network error.
ENV CURL_RETRY="--retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 10"

RUN curl --proto '=https' --tlsv1.2 -sSf $CURL_RETRY https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} && \
    chmod -R a+w ${RUSTUP_HOME} ${CARGO_HOME}

RUN curl -LsSf $CURL_RETRY https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# reckless's poetry-based plugin installs (setup.sh: `uv tool install poetry`).
RUN UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin \
        uv tool install poetry && \
    chmod -R a+rX /opt/uv-tools

# sccache is not included yet; add it together with a compile cache.

# bitcoind/elementsd: kept off PATH so only the daemon under test is
# reachable; exactly one of these is prepended to PATH at run time.
ARG BITCOIN_VERSION=27.1
ARG ELEMENTS_VERSION=23.2.1
RUN mkdir -p /opt/bitcoin /opt/elements && \
    curl -fL $CURL_RETRY -o /tmp/bitcoin.tar.gz \
        https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf /tmp/bitcoin.tar.gz -C /opt/bitcoin --strip-components=1 && \
    curl -fL $CURL_RETRY -o /tmp/elements.tar.gz \
        https://github.com/ElementsProject/elements/releases/download/elements-${ELEMENTS_VERSION}/elements-${ELEMENTS_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf /tmp/elements.tar.gz -C /opt/elements --strip-components=1 && \
    rm -f /tmp/bitcoin.tar.gz /tmp/elements.tar.gz

# Full repo as build context, so `uv sync` and `cargo fetch` see the real
# workspace manifests rather than a hand-picked subset.
WORKDIR /build
COPY . .
RUN uv python install 3.12 && \
    uv sync --locked --all-extras --all-groups --python 3.12 && \
    cargo fetch --locked --manifest-path Cargo.toml && \
    chmod -R a+w ${UV_PROJECT_ENVIRONMENT} ${CARGO_HOME} && \
    chmod -R a+rX ${UV_PYTHON_INSTALL_DIR}
WORKDIR /
RUN rm -rf /build
