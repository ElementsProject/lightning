# This Dockerfile is used by buildx to build ARM64, AMD64, and ARM32 Docker images from an AMD64 host.
# To speed up the build process, we are cross-compiling rather than relying on QEMU.
# There are four main stages:
# * downloader: Downloads specific binaries needed for c-lightning for each architecture.
# * builder: Cross-compiles for each architecture.
# * builder-python: Builds Python dependencies for cln-rest with QEMU.
# * final: Creates the runtime image.

ARG BASE_DISTRO="debian:bullseye-slim"

FROM --platform=$BUILDPLATFORM ${BASE_DISTRO} as base-downloader
RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr wget qemu-user-static binfmt-support

FROM base-downloader as base-downloader-linux-amd64
ENV TARBALL_ARCH_FINAL=x86_64-linux-gnu

FROM base-downloader as base-downloader-linux-arm64
ENV TARBALL_ARCH_FINAL=aarch64-linux-gnu

FROM base-downloader as base-downloader-linux-arm
ENV TARBALL_ARCH_FINAL=arm-linux-gnueabihf

FROM base-downloader-${TARGETOS}-${TARGETARCH} as downloader

RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr wget

WORKDIR /opt


ENV BITCOIN_VERSION=22.0
ENV BITCOIN_TARBALL bitcoin-${BITCOIN_VERSION}-${TARBALL_ARCH_FINAL}.tar.gz
ENV BITCOIN_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/$BITCOIN_TARBALL
ENV BITCOIN_ASC_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/SHA256SUMS

RUN mkdir /opt/bitcoin && cd /opt/bitcoin \
    && wget -qO $BITCOIN_TARBALL "$BITCOIN_URL" \
    && wget -qO bitcoin "$BITCOIN_ASC_URL" \
    && grep $BITCOIN_TARBALL bitcoin | tee SHA256SUMS \
    && sha256sum -c SHA256SUMS \
    && BD=bitcoin-$BITCOIN_VERSION/bin \
    && tar -xzvf $BITCOIN_TARBALL $BD/ --strip-components=1 \
    && rm $BITCOIN_TARBALL

ENV LITECOIN_VERSION 0.16.3
ENV LITECOIN_URL https://download.litecoin.org/litecoin-${LITECOIN_VERSION}/linux/litecoin-${LITECOIN_VERSION}-${TARBALL_ARCH_FINAL}.tar.gz

# install litecoin binaries
RUN mkdir /opt/litecoin && cd /opt/litecoin \
    && wget -qO litecoin.tar.gz "$LITECOIN_URL" \
    && tar -xzvf litecoin.tar.gz litecoin-$LITECOIN_VERSION/bin/litecoin-cli --strip-components=1 --exclude=*-qt \
    && rm litecoin.tar.gz

FROM --platform=linux/amd64 ${BASE_DISTRO} as base-builder
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        curl \
        dirmngr \
        gettext \
        git \
        gnupg \
        jq \
        libpq-dev \
        libtool \
        libffi-dev \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        python3.9 \
        python3-dev \
        python3-mako \
        python3-pip \
        python3-venv \
        python3-setuptools \
        libev-dev \
        libevent-dev \
        qemu-user-static \
        wget \
        unzip \
        tclsh

ENV PYTHON_VERSION=3
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.9 1
RUN pip3 install --upgrade pip setuptools wheel

RUN wget -q https://zlib.net/fossils/zlib-1.2.13.tar.gz -O zlib.tar.gz && \
    wget -q https://www.sqlite.org/2019/sqlite-src-3290000.zip -O sqlite.zip

WORKDIR /opt/lightningd
COPY . /tmp/lightning
RUN git clone --recursive /tmp/lightning . && \
    git checkout $(git --work-tree=/tmp/lightning --git-dir=/tmp/lightning/.git rev-parse HEAD)

# Do not build python plugins (clnrest & wss-proxy) here, python doesn't support cross compilation.
RUN sed -i '/^clnrest\|^wss-proxy/d' pyproject.toml && \
    /root/.local/bin/poetry export -o requirements.txt --without-hashes
RUN pip3 install -r requirements.txt && pip3 cache purge
WORKDIR /

FROM base-builder as base-builder-linux-amd64

FROM base-builder as base-builder-linux-arm64
ENV target_host=aarch64-linux-gnu \
    target_host_rust=aarch64-unknown-linux-gnu \
    target_host_qemu=qemu-aarch64-static

RUN apt-get install -qq -y --no-install-recommends \
        libc6-arm64-cross \
        gcc-${target_host} \
        g++-${target_host}

ENV AR=${target_host}-ar \
AS=${target_host}-as \
CC=${target_host}-gcc \
CXX=${target_host}-g++ \
LD=${target_host}-ld \
STRIP=${target_host}-strip \
QEMU_LD_PREFIX=/usr/${target_host} \
HOST=${target_host} \
TARGET=${target_host_rust} \
RUSTUP_INSTALL_OPTS="--target ${target_host_rust} --default-host ${target_host_rust}" \
PKG_CONFIG_PATH="/usr/${target_host}/lib/pkgconfig"

ENV \
ZLIB_CONFIG="--prefix=${QEMU_LD_PREFIX}" \
SQLITE_CONFIG="--host=${target_host} --prefix=$QEMU_LD_PREFIX"

FROM base-builder as base-builder-linux-arm

ENV target_host=arm-linux-gnueabihf \
    target_host_rust=armv7-unknown-linux-gnueabihf \
    target_host_qemu=qemu-arm-static

RUN apt-get install -qq -y --no-install-recommends \
        libc6-armhf-cross \
        gcc-${target_host} \
        g++-${target_host}

ENV AR=${target_host}-ar \
AS=${target_host}-as \
CC=${target_host}-gcc \
CXX=${target_host}-g++ \
LD=${target_host}-ld \
STRIP=${target_host}-strip \
QEMU_LD_PREFIX=/usr/${target_host} \
HOST=${target_host} \
TARGET=${target_host_rust} \
RUSTUP_INSTALL_OPTS="--target ${target_host_rust} --default-host ${target_host_rust}" \
PKG_CONFIG_PATH="/usr/${target_host}/lib/pkgconfig"

ENV \
ZLIB_CONFIG="--prefix=${QEMU_LD_PREFIX}" \
SQLITE_CONFIG="--host=${target_host} --prefix=$QEMU_LD_PREFIX"

FROM base-builder-${TARGETOS}-${TARGETARCH} as builder

ENV LIGHTNINGD_VERSION=master

RUN mkdir zlib && tar xvf zlib.tar.gz -C zlib --strip-components=1 \
    && cd zlib \
    && ./configure ${ZLIB_CONFIG} \
    && make \
    && make install && cd .. && \
    rm zlib.tar.gz && \
    rm -rf zlib

RUN unzip sqlite.zip \
    && cd sqlite-* \
    && ./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension ${SQLITE_CONFIG} \
    && make \
    && make install && cd .. && rm sqlite.zip && rm -rf sqlite-*

ENV RUST_PROFILE=release
ENV PATH=$PATH:/root/.cargo/bin/
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y ${RUSTUP_INSTALL_OPTS}
RUN rustup toolchain install stable --component rustfmt --allow-downgrade

COPY --from=downloader /usr/bin/${target_host_qemu} /usr/bin/${target_host_qemu}
WORKDIR /opt/lightningd

# If cross-compiling, need to tell it to cargo.
RUN ( ! [ -n "${target_host}" ] ) || \
    (mkdir -p .cargo && echo "[target.${target_host_rust}]\nlinker = \"${target_host}-gcc\"" > .cargo/config)

# Weird errors with cargo for cln-grpc on arm7 https://github.com/ElementsProject/lightning/issues/6596
RUN ( ! [ "${target_host}" = "arm-linux-gnueabihf" ] ) || \
    (sed -i '/documentation = "https:\/\/docs.rs\/cln-grpc"/a include = ["**\/*.*"]' cln-grpc/Cargo.toml)

# Ensure that the desired grpcio-tools & protobuf versions are installed
# https://github.com/ElementsProject/lightning/pull/7376#issuecomment-2161102381
RUN /root/.local/bin/poetry lock --no-update && \
    /root/.local/bin/poetry install

RUN ./configure --prefix=/tmp/lightning_install --enable-static && \
    make && \
    /root/.local/bin/poetry run make install

# We need to build python plugins on the target's arch because python doesn't support cross build
FROM ${BASE_DISTRO} as builder-python
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
        git \
        curl \
        libtool \
        pkg-config \
        autoconf \
        automake \
        build-essential \
        libffi-dev \
        libssl-dev \
        python3.9 \
        python3-dev \
        python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.9 1
ENV PATH=$PATH:/root/.cargo/bin/
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN rustup toolchain install stable --component rustfmt --allow-downgrade

WORKDIR /opt/lightningd
COPY plugins/clnrest/requirements.txt plugins/clnrest/requirements.txt
COPY plugins/wss-proxy/requirements.txt plugins/wss-proxy/requirements.txt
ENV PYTHON_VERSION=3
RUN pip3 install -r plugins/clnrest/requirements.txt && \
    pip3 install -r plugins/wss-proxy/requirements.txt && \
    pip3 cache purge

FROM ${BASE_DISTRO} as final

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tini \
      socat \
      inotify-tools \
      jq \
      python3.9 \
      python3-pip \
      libpq5 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835
ENV LIGHTNINGD_PORT=9735
ENV LIGHTNINGD_NETWORK=bitcoin

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config
VOLUME [ "/root/.lightning" ]

COPY --from=builder /tmp/lightning_install/ /usr/local/
COPY --from=builder-python /usr/local/lib/python3.9/dist-packages/ /usr/local/lib/python3.9/dist-packages/
COPY --from=downloader /opt/bitcoin/bin /usr/bin
COPY --from=downloader /opt/litecoin/bin /usr/bin
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "/usr/bin/tini", "-g", "--", "./entrypoint.sh" ]
