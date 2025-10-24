# syntax=docker/dockerfile:1.7-labs

FROM --platform=${BUILDPLATFORM} debian:bookworm-slim AS base-host

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

FROM --platform=${TARGETPLATFORM} debian:bookworm-slim AS base-target

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

FROM base-host AS downloader-linux-amd64

ARG target_arch=x86_64-linux-gnu

FROM base-host AS downloader-linux-arm64

ARG target_arch=aarch64-linux-gnu

FROM base-host AS downloader-linux-arm

ARG target_arch=arm-linux-gnueabihf

FROM downloader-${TARGETOS}-${TARGETARCH} AS downloader

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
        gnupg

ARG BITCOIN_VERSION=27.1
ARG BITCOIN_URL=https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}
ARG BITCOIN_TARBALL=bitcoin-${BITCOIN_VERSION}-${target_arch}.tar.gz

WORKDIR /opt/bitcoin

ADD ${BITCOIN_URL}/${BITCOIN_TARBALL}    .
ADD ${BITCOIN_URL}/SHA256SUMS            .
ADD ${BITCOIN_URL}/SHA256SUMS.asc        .
COPY contrib/keys/bitcoin/               gpg/

RUN gpg --quiet --import gpg/* && \
    gpg --verify SHA256SUMS.asc SHA256SUMS && \
    sha256sum -c SHA256SUMS --ignore-missing

RUN tar xzf ${BITCOIN_TARBALL} --strip-components=1

FROM base-host AS base-builder

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        git \
        autoconf \
        automake \
        bison \
        flex \
        jq \
        libtool \
        gettext \
        protobuf-compiler

WORKDIR /opt

ADD --chmod=750 https://astral.sh/uv/install.sh      install-uv.sh
ADD --chmod=750 https://sh.rustup.rs                 install-rust.sh

WORKDIR /opt/lightningd

COPY --exclude=.git/ . .

FROM base-builder AS base-builder-linux-amd64

ARG target_arch=x86_64-linux-gnu
ARG target_arch_gcc=x86-64-linux-gnu
ARG target_arch_dpkg=amd64
ARG target_arch_rust=x86_64-unknown-linux-gnu
ARG COPTFLAGS="-O2 -march=x86-64"

FROM base-builder AS base-builder-linux-arm64

ARG target_arch=aarch64-linux-gnu
ARG target_arch_gcc=aarch64-linux-gnu
ARG target_arch_dpkg=arm64
ARG target_arch_rust=aarch64-unknown-linux-gnu
ARG COPTFLAGS="-O2 -march=armv8-a"

FROM base-builder AS base-builder-linux-arm

ARG target_arch=arm-linux-gnueabihf
ARG target_arch_gcc=arm-linux-gnueabihf
ARG target_arch_dpkg=armhf
ARG target_arch_rust=armv7-unknown-linux-gnueabihf
#TODO: bug with -O2 in armv7, see https://github.com/ElementsProject/lightning/issues/8501
ARG COPTFLAGS="-O1 -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard"

FROM base-builder-${TARGETOS}-${TARGETARCH} AS builder

ENV LIGHTNINGD_VERSION=master

RUN dpkg --add-architecture ${target_arch_dpkg}

#TODO: python3-dev needs QEMU for post install scripts. find a workaround to not use QEMU
RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
        pkg-config:${target_arch_dpkg} \
        libffi-dev:${target_arch_dpkg} \
        python3-dev:${target_arch_dpkg} \
        libicu-dev:${target_arch_dpkg} \
        zlib1g-dev:${target_arch_dpkg} \
        libsqlite3-dev:${target_arch_dpkg} \
        libpq-dev:${target_arch_dpkg} \
        crossbuild-essential-${target_arch_dpkg}

ARG AR=${target_arch}-ar
ARG AS=${target_arch}-as
ARG CC=${target_arch}-gcc
ARG CXX=${target_arch}-g++
ARG LD=${target_arch}-ld
ARG STRIP=${target_arch}-strip
ARG TARGET=${target_arch_rust}
ARG RUST_PROFILE=release

#TODO: set all the following cargo config options via env variables (https://doc.rust-lang.org/cargo/reference/environment-variables.html)
RUN mkdir -p .cargo && tee .cargo/config.toml <<EOF

[build]
target = "${target_arch_rust}"
rustflags = ["-C", "target-cpu=generic"]

[target.${target_arch_rust}]
linker = "${CC}"

EOF

WORKDIR /opt

RUN ./install-uv.sh -q
RUN ./install-rust.sh -y -q --profile minimal --component rustfmt --target ${target_arch_rust}

ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

WORKDIR /opt/lightningd

#TODO: find a way to avoid copying the .git/ directory (it always invalidates the cache)
COPY .git/ .git/
RUN git submodule update --init --recursive --jobs $(nproc) --depth 1

RUN ./configure --prefix=/tmp/lightning_install --enable-static --disable-compat --disable-valgrind
RUN uv run make install-program -j$(nproc)

RUN find /tmp/lightning_install -type f -executable -exec \
    file {} + | \
    awk -F: '/ELF/ {print $1}' | \
    xargs -r ${STRIP} --strip-unneeded

FROM base-target AS final

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
        inotify-tools \
        socat \
        jq \
        libpq5 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=downloader    /opt/bitcoin/bin/bitcoin-cli      /usr/bin/
COPY --from=builder       /tmp/lightning_install/           /usr/local/

COPY tools/docker-entrypoint.sh    /entrypoint.sh

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835
ENV LIGHTNINGD_PORT=9735
ENV LIGHTNINGD_NETWORK=bitcoin

EXPOSE 9735 9835
VOLUME ["/root/.lightning"]
ENTRYPOINT ["/entrypoint.sh"]
