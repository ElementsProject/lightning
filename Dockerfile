# This dockerfile is meant to compile a core-lightning x64 image
# It is using multi stage build:
# * downloader: Download litecoin/bitcoin and qemu binaries needed for core-lightning
# * builder: Compile core-lightning dependencies, then core-lightning itself with static linking
# * final: Copy the binaries required at runtime
# The resulting image uploaded to dockerhub will only contain what is needed for runtime.
# From the root of the repository, run "docker build -t yourimage:yourtag ."
FROM debian:bullseye-slim as downloader

RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr wget

WORKDIR /opt


ARG BITCOIN_VERSION=22.0
ARG TARBALL_ARCH=x86_64-linux-gnu
ENV TARBALL_ARCH_FINAL=$TARBALL_ARCH
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

FROM debian:bullseye-slim as builder

ENV LIGHTNINGD_VERSION=master
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
        jq

RUN wget -q https://zlib.net/fossils/zlib-1.2.13.tar.gz \
    && tar xvf zlib-1.2.13.tar.gz \
    && cd zlib-1.2.13 \
    && ./configure \
    && make \
    && make install && cd .. && \
    rm zlib-1.2.13.tar.gz && \
    rm -rf zlib-1.2.13

RUN apt-get install -y --no-install-recommends unzip tclsh \
    && wget -q https://www.sqlite.org/2019/sqlite-src-3290000.zip \
    && unzip sqlite-src-3290000.zip \
    && cd sqlite-src-3290000 \
    && ./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension \
    && make \
    && make install && cd .. && rm sqlite-src-3290000.zip && rm -rf sqlite-src-3290000

USER root
ENV RUST_PROFILE=release
ENV PATH=$PATH:/root/.cargo/bin/
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN rustup toolchain install stable --component rustfmt --allow-downgrade

WORKDIR /opt/lightningd
COPY . /tmp/lightning

RUN git clone --recursive /tmp/lightning . && \
    git checkout $(git --work-tree=/tmp/lightning --git-dir=/tmp/lightning/.git rev-parse HEAD)

ENV PYTHON_VERSION=3
RUN curl -sSL https://install.python-poetry.org | python3 -

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.9 1

RUN pip3 install --upgrade pip setuptools wheel
RUN pip3 wheel cryptography
RUN pip3 install grpcio-tools

RUN /root/.local/bin/poetry export -o requirements.txt --without-hashes --with dev
RUN pip3 install -r requirements.txt

RUN ./configure --prefix=/tmp/lightning_install --enable-static && \
    make && \
    /root/.local/bin/poetry run make install

FROM debian:bullseye-slim as final

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tini \
      socat \
      inotify-tools \
      python3.9 \
      python3-pip \
      qemu-user-static \
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
COPY --from=builder /usr/local/lib/python3.9/dist-packages/ /usr/local/lib/python3.9/dist-packages/
COPY --from=downloader /opt/bitcoin/bin /usr/bin
COPY --from=downloader /opt/litecoin/bin /usr/bin
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "/usr/bin/tini", "-g", "--", "./entrypoint.sh" ]
