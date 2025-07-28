ARG TARGETOS
ARG TARGETARCH

ARG BASE_DISTRO="debian:bookworm-slim"

FROM ${BASE_DISTRO} AS base-downloader

FROM base-downloader AS base-downloader-linux-amd64
ARG TARBALL_ARCH_FINAL=x86_64-linux-gnu

FROM base-downloader AS base-downloader-linux-arm64
ARG TARBALL_ARCH_FINAL=aarch64-linux-gnu

FROM base-downloader AS base-downloader-linux-arm
ARG TARBALL_ARCH_FINAL=arm-linux-gnueabihf

FROM base-downloader-${TARGETOS}-${TARGETARCH} AS downloader

RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
        gnupg

ARG BITCOIN_VERSION=27.1
ARG BITCOIN_URL=https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}
ARG BITCOIN_TARBALL=bitcoin-${BITCOIN_VERSION}-${TARBALL_ARCH_FINAL}.tar.gz

WORKDIR /opt/bitcoin

ADD ${BITCOIN_URL}/${BITCOIN_TARBALL}    .
ADD ${BITCOIN_URL}/SHA256SUMS            .
ADD ${BITCOIN_URL}/SHA256SUMS.asc        .
COPY gpg/bitcoin/                        gpg/

RUN gpg --import gpg/* && \
    gpg --verify SHA256SUMS.asc SHA256SUMS && \
    sha256sum -c SHA256SUMS --ignore-missing

RUN tar xzf ${BITCOIN_TARBALL} --strip-components=1

ARG LITECOIN_VERSION=0.16.3
ARG LITECOIN_BASE_URL=https://download.litecoin.org/litecoin-${LITECOIN_VERSION}
ARG LITECOIN_URL=${LITECOIN_BASE_URL}/linux
ARG LITECOIN_TARBALL=litecoin-${LITECOIN_VERSION}-${TARBALL_ARCH_FINAL}.tar.gz

WORKDIR /opt/litecoin

ADD ${LITECOIN_URL}/${LITECOIN_TARBALL}        .
ADD ${LITECOIN_URL}/${LITECOIN_TARBALL}.asc    .
ADD ${LITECOIN_BASE_URL}/SHA256SUMS.asc        .
COPY gpg/litecoin/                             gpg/

RUN gpg --import gpg/* && \
    gpg --verify SHA256SUMS.asc && \
    gpg --verify ${LITECOIN_TARBALL}.asc ${LITECOIN_TARBALL} && \
    sha256sum -c SHA256SUMS.asc --ignore-missing

RUN tar xzf ${LITECOIN_TARBALL} --strip-components=1

FROM ${BASE_DISTRO} AS base-builder

RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        gnupg \
        wget \
        python3 \
        autoconf \
        automake \
        libicu-dev \
        pkg-config \
        bison \
        flex \
        jq \
        libtool \
        gettext \
        protobuf-compiler \
        qemu-user-static

ARG ZLIB_URL=https://github.com/madler/zlib/releases/download
ARG ZLIB_VERSION=1.2.13
ARG ZLIB_TARBALL=zlib-${ZLIB_VERSION}.tar.gz

WORKDIR /opt/zlib

ADD ${ZLIB_URL}/v${ZLIB_VERSION}/${ZLIB_TARBALL}        .
ADD ${ZLIB_URL}/v${ZLIB_VERSION}/${ZLIB_TARBALL}.asc    . 
COPY gpg/zlib/                                          gpg/

RUN gpg --import gpg/* && \
    gpg --verify ${ZLIB_TARBALL}.asc ${ZLIB_TARBALL}

#TODO: verify checksum

ARG SQLITE_URL=https://www.sqlite.org
ARG SQLITE_YEAR=2019
ARG SQLITE_VERSION=3290000
ARG SQLITE_TARBALL=sqlite-autoconf-${SQLITE_VERSION}.tar.gz

WORKDIR /opt/sqlite

ADD ${SQLITE_URL}/${SQLITE_YEAR}/${SQLITE_TARBALL}    .
#TODO: add sig
#TODO: add gpgs

#TODO verify gpgs

ARG POSTGRES_URL=https://ftp.postgresql.org/pub/source
ARG POSTGRES_VERSION=17.1
ARG POSTGRES_TARBALL=postgresql-${POSTGRES_VERSION}.tar.gz

WORKDIR /opt/postgres

ADD ${POSTGRES_URL}/v${POSTGRES_VERSION}/${POSTGRES_TARBALL}           .
ADD ${POSTGRES_URL}/v${POSTGRES_VERSION}/${POSTGRES_TARBALL}.sha256    .
#TODO: add gpgs

#TODO verify gpgs

RUN sha256sum -c ${POSTGRES_TARBALL}.sha256

WORKDIR /opt

ADD --chmod=750 https://install.python-poetry.org    install-poetry.py
ADD --chmod=750 https://sh.rustup.rs                 install-rust.sh

WORKDIR /opt/lightningd

#TODO: fix caching of this layer
COPY . .

RUN git submodule update --init --recursive

FROM base-builder AS base-builder-linux-amd64

ARG target_host=x86_64-linux-gnu
ARG target_host_rust=x86_64-unknown-linux-gnu

FROM base-builder AS base-builder-linux-arm64

ARG target_host=aarch64-linux-gnu
ARG target_host_rust=aarch64-unknown-linux-gnu

FROM base-builder AS base-builder-linux-arm

ARG target_host=arm-linux-gnueabihf
ARG target_host_rust=armv7-unknown-linux-gnueabihf

FROM base-builder-${TARGETOS}-${TARGETARCH} AS builder

ENV RUST_PROFILE=release
ENV LIGHTNINGD_VERSION=master

ARG AR=${target_host}-ar
ARG AS=${target_host}-as
ARG CC=${target_host}-gcc
ARG CXX=${target_host}-g++
ARG LD=${target_host}-ld
ARG STRIP=${target_host}-strip
ARG QEMU_LD_PREFIX=/usr/${target_host}
ARG TARGET=${target_host_rust}
ARG PKG_CONFIG_PATH=${QEMU_LD_PREFIX}/lib/pkgconfig

WORKDIR /opt

RUN ./install-poetry.py
RUN ./install-rust.sh -y --target ${target_host_rust} --profile minimal --component rustfmt

#TODO: error here when building for `arm`
ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

WORKDIR /opt/zlib

RUN tar xzf ${ZLIB_TARBALL} --strip-components=1
RUN ./configure --prefix=${QEMU_LD_PREFIX}
RUN make -j$(nproc)
RUN make -j$(nproc) install

WORKDIR /opt/sqlite

RUN tar xzf ${SQLITE_TARBALL} --strip-components=1
RUN ./configure --host=${target_host} --prefix=${QEMU_LD_PREFIX} --enable-static --disable-readline --disable-threadsafe --disable-load-extension
RUN make -j$(nproc)
RUN make -j$(nproc) install

WORKDIR /opt/postgres

RUN tar xzf ${POSTGRES_TARBALL} --strip-components=1
RUN ./configure --host=${target_host} --prefix=${QEMU_LD_PREFIX} --without-readline
RUN make -j$(nproc) install -C src/include
RUN make -j$(nproc) install -C src/interfaces/libpq

RUN mkdir -p /tmp/postgres_install/lib && \
    cp -a ${QEMU_LD_PREFIX}/lib/libpq.* /tmp/postgres_install/lib/

WORKDIR /opt/lightningd

RUN mkdir -p .cargo && tee .cargo/config.toml <<-EOF
  [target.${target_host_rust}]
  linker = "${target_host}-gcc"
EOF

ARG POETRY_VIRTUALENVS_CREATE=false

RUN poetry lock && \
    poetry install --no-root --no-interaction --no-ansi

RUN ./configure --prefix=/tmp/lightning_install --enable-static
RUN poetry run make -j$(nproc) install

RUN for f in /tmp/lightning_install/bin/*; do \
  if file "$f" | grep -q ELF; then \
    ${STRIP} --strip-unneeded "$f"; \
  fi; \
done

FROM ${BASE_DISTRO} AS final

RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
        inotify-tools \
        socat \
        jq && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=downloader    /opt/bitcoin/bin/bitcoin-cli      /usr/bin/
COPY --from=downloader    /opt/litecoin/bin/litecoin-cli    /usr/bin/
COPY --from=builder       /tmp/lightning_install/           /usr/local/
COPY --from=builder       /tmp/postgres_install/lib/        /usr/lib/

COPY tools/docker-entrypoint.sh    /entrypoint.sh

#TODO: user creation. user permissions on volume.

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835
ENV LIGHTNINGD_PORT=9735
ENV LIGHTNINGD_NETWORK=bitcoin

EXPOSE 9735 9835
VOLUME ["/root/.lightning"]
ENTRYPOINT ["/entrypoint.sh"]