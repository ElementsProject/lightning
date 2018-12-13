FROM debian:stretch-slim as downloader

RUN set -ex \
	&& apt-get update \
	&& apt-get install -qq --no-install-recommends ca-certificates dirmngr wget \
     qemu qemu-user-static qemu-user binfmt-support

WORKDIR /opt

ARG BITCOIN_VERSION=0.17.0
ENV BITCOIN_TARBALL bitcoin-$BITCOIN_VERSION-arm-linux-gnueabihf.tar.gz
ENV BITCOIN_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/$BITCOIN_TARBALL
ENV BITCOIN_ASC_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/SHA256SUMS.asc

RUN mkdir /opt/bitcoin && cd /opt/bitcoin \
    && wget -qO $BITCOIN_TARBALL "$BITCOIN_URL" \
    && wget -qO bitcoin.asc "$BITCOIN_ASC_URL" \
    && grep $BITCOIN_TARBALL bitcoin.asc | tee SHA256SUMS.asc \
    && sha256sum -c SHA256SUMS.asc \
    && BD=bitcoin-$BITCOIN_VERSION/bin \
    && tar -xzvf $BITCOIN_TARBALL $BD/bitcoin-cli --strip-components=1 \
    && rm $BITCOIN_TARBALL

ENV LITECOIN_VERSION 0.14.2
ENV LITECOIN_TARBALL litecoin-$LITECOIN_VERSION-arm-linux-gnueabihf.tar.gz
ENV LITECOIN_URL https://download.litecoin.org/litecoin-$LITECOIN_VERSION/linux/$LITECOIN_TARBALL
ENV LITECOIN_SHA256 e79f2a8e8e1b9920d07cff8482237b56aa4be2623103d3d2825ce09a2cc2f6d7

# install litecoin binaries
RUN mkdir /opt/litecoin && cd /opt/litecoin \
    && wget -qO litecoin.tar.gz "$LITECOIN_URL" \
    && echo "$LITECOIN_SHA256  litecoin.tar.gz" | sha256sum -c - \
    && BD=litecoin-$LITECOIN_VERSION/bin \
    && tar -xzvf litecoin.tar.gz $BD/litecoin-cli --strip-components=1 --exclude=*-qt \
    && rm litecoin.tar.gz

FROM arm32v7/debian:stretch-slim as builder

COPY --from=downloader /usr/bin/qemu-arm-static /usr/bin/qemu-arm-static
ENV LIGHTNINGD_VERSION=master
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates autoconf automake build-essential git libtool python python3 wget gnupg dirmngr git \
  libgmp-dev libsqlite3-dev zlib1g-dev

WORKDIR /opt/lightningd
COPY . .
ARG DEVELOPER=0
RUN ./configure && make -j3 DEVELOPER=${DEVELOPER} && cp lightningd/lightning* cli/lightning-cli /usr/bin/

# This is a manifest image, will pull the image with the same arch as the builder machine
FROM microsoft/dotnet:2.1.500-sdk AS dotnetbuilder

RUN apt-get -y update && apt-get -y install git

WORKDIR /source

RUN git clone https://github.com/dgarage/NBXplorer && cd NBXplorer && git checkout v2.0.0.2

# Cache some dependencies
RUN cd NBXplorer/NBXplorer.NodeWaiter && dotnet restore && cd ..
RUN cd NBXplorer/NBXplorer.NodeWaiter && \
    dotnet publish --output /app/ --configuration Release

FROM microsoft/dotnet:2.1.6-runtime-stretch-slim-arm32v7 as final
COPY --from=downloader /usr/bin/qemu-arm-static /usr/bin/qemu-arm-static
RUN apt-get update && apt-get install -y --no-install-recommends socat libgmp-dev inotify-tools libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/* 

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_PORT=9835

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config
VOLUME [ "/root/.lightning" ]

COPY --from=builder /opt/lightningd/cli/lightning-cli /usr/bin
COPY --from=builder /opt/lightningd/lightningd/lightning* /usr/bin/
COPY --from=downloader /opt/bitcoin/bin /usr/bin
COPY --from=downloader /opt/litecoin/bin /usr/bin
COPY --from=dotnetbuilder /app /opt/NBXplorer.NodeWaiter
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "./entrypoint.sh" ]
