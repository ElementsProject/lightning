# This dockerfile is meant to cross compile with a x64 machine for a arm64v8 host
# It is using multi stage build: 
# * downloader: Download litecoin/bitcoin and qemu binaries needed for Core Lightning
# * builder: Cross compile Core Lightning dependencies, then Core Lightning itself with static linking
# * final: Copy the binaries required at runtime
# The resulting image uploaded to dockerhub will only contain what is needed for runtime.
# From the root of the repository, run "docker build -t yourimage:yourtag -f contrib/linuxarm64v8.Dockerfile ."
FROM debian:bullseye-slim as downloader

RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr wget \
     qemu-user-static binfmt-support

WORKDIR /opt

RUN wget -qO /opt/tini "https://github.com/krallin/tini/releases/download/v0.18.0/tini-arm64" \
    && echo "7c5463f55393985ee22357d976758aaaecd08defb3c5294d353732018169b019 /opt/tini" | sha256sum -c - \
    && chmod +x /opt/tini

ARG BITCOIN_VERSION=22.0
ENV BITCOIN_TARBALL bitcoin-$BITCOIN_VERSION-aarch64-linux-gnu.tar.gz
ENV BITCOIN_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/$BITCOIN_TARBALL
ENV BITCOIN_ASC_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/SHA256SUMS

RUN mkdir /opt/bitcoin && cd /opt/bitcoin \
    && wget -qO $BITCOIN_TARBALL "$BITCOIN_URL" \
    && wget -qO bitcoin "$BITCOIN_ASC_URL" \
    && grep $BITCOIN_TARBALL bitcoin | tee SHA256SUMS \
    && sha256sum -c SHA256SUMS \
    && BD=bitcoin-$BITCOIN_VERSION/bin \
    && tar -xzvf $BITCOIN_TARBALL $BD/bitcoin-cli --strip-components=1 \
    && rm $BITCOIN_TARBALL


ENV LITECOIN_VERSION 0.16.3
ENV LITECOIN_URL https://download.litecoin.org/litecoin-${LITECOIN_VERSION}/linux/litecoin-${LITECOIN_VERSION}-aarch64-linux-gnu.tar.gz
ENV LITECOIN_SHA256 3284316bdf10496528b3cd730877be3a1ea34add49dfc88fe0e96eb9925c1f08

# install litecoin binaries
RUN mkdir /opt/litecoin && cd /opt/litecoin \
    && wget -qO litecoin.tar.gz "$LITECOIN_URL" \
    && echo "$LITECOIN_SHA256  litecoin.tar.gz" | sha256sum -c - \
    && BD=litecoin-$LITECOIN_VERSION/bin \
    && tar -xzvf litecoin.tar.gz $BD/litecoin-cli --strip-components=1 --exclude=*-qt \
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
        python3 \
        python3-dev \
        python3-mako \
        python3-pip \
        python3-venv \
        python3-setuptools \
        wget && \
    # arm64v8 compilers
    apt-get install -qq -y --no-install-recommends \
        libc6-arm64-cross \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu

ENV target_host=aarch64-linux-gnu

ENV AR=${target_host}-ar \
AS=${target_host}-as \
CC=${target_host}-gcc \
CXX=${target_host}-g++ \
LD=${target_host}-ld \
STRIP=${target_host}-strip \
QEMU_LD_PREFIX=/usr/${target_host} \
HOST=${target_host}

RUN wget -q https://zlib.net/fossils/zlib-1.2.13.tar.gz \
&& tar xvf zlib-1.2.13.tar.gz \
&& cd zlib-1.2.13 \
&& ./configure --prefix=$QEMU_LD_PREFIX \
&& make \
&& make install && cd .. && rm zlib-1.2.13.tar.gz && rm -rf zlib-1.2.13

RUN apt-get install -y --no-install-recommends unzip tclsh \
&& wget -q https://www.sqlite.org/2019/sqlite-src-3290000.zip \
&& unzip sqlite-src-3290000.zip \
&& cd sqlite-src-3290000 \
&& ./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host=${target_host} --prefix=$QEMU_LD_PREFIX \
&& make \
&& make install && cd .. && rm sqlite-src-3290000.zip && rm -rf sqlite-src-3290000

RUN wget -q https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz \
&& tar xvf gmp-6.1.2.tar.xz \
&& cd gmp-6.1.2 \
&& ./configure --disable-assembly --prefix=$QEMU_LD_PREFIX --host=${target_host} \
&& make \
&& make install && cd .. && rm gmp-6.1.2.tar.xz && rm -rf gmp-6.1.2
COPY --from=downloader /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
WORKDIR /opt/lightningd
COPY . /tmp/lightning
RUN git clone --recursive /tmp/lightning . && \
    git checkout $(git --work-tree=/tmp/lightning --git-dir=/tmp/lightning/.git rev-parse HEAD)

ARG DEVELOPER=0
ENV PYTHON_VERSION=3

RUN curl -sSL https://install.python-poetry.org | python3 - \
&& pip3 install -U pip \
&& pip3 install -U wheel \
&& /root/.local/bin/poetry install

RUN ./configure --prefix=/tmp/lightning_install --enable-static && \
make DEVELOPER=${DEVELOPER} && \
/root/.local/bin/poetry run make install

FROM arm64v8/debian:bullseye-slim as final
COPY --from=downloader /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=downloader /opt/tini /usr/bin/tini

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      socat \
      inotify-tools \
      python3 \
      python3-pip \
      libpq5 && \
    rm -rf /var/lib/apt/lists/*

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835
ENV LIGHTNINGD_PORT=9735
ENV LIGHTNINGD_NETWORK=bitcoin

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config
VOLUME [ "/root/.lightning" ]
COPY --from=builder /tmp/lightning_install/ /usr/local/
COPY --from=downloader /opt/bitcoin/bin /usr/bin
COPY --from=downloader /opt/litecoin/bin /usr/bin
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "/usr/bin/tini", "-g", "--", "./entrypoint.sh" ]
