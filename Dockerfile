FROM ubuntu:16.04 as builder
ENV LIGHTNINGD_VERSION=master
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates autoconf automake build-essential git libtool libgmp-dev \
  libsqlite3-dev python python3 wget

WORKDIR /opt/lightningd
COPY . .
RUN make && cp lightningd/lightning* cli/lightning-cli /usr/bin/

ENV BITCOIN_VERSION 0.16.0
ENV BITCOIN_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz
ENV BITCOIN_SHA256 e6322c69bcc974a29e6a715e0ecb8799d2d21691d683eeb8fef65fc5f6a66477
ENV BITCOIN_ASC_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/SHA256SUMS.asc
ENV BITCOIN_PGP_KEY 01EA5486DE18A882D4C2684590C8019E36C2E964
RUN mkdir /opt/bitcoin && cd /opt/bitcoin \
    && wget -qO bitcoin.tar.gz "$BITCOIN_URL" \
    && echo "$BITCOIN_SHA256 bitcoin.tar.gz" | sha256sum -c - \
    && gpg --keyserver keyserver.ubuntu.com --recv-keys "$BITCOIN_PGP_KEY" \
    && wget -qO bitcoin.asc "$BITCOIN_ASC_URL" \
    && gpg --verify bitcoin.asc \
    && BD=bitcoin-$BITCOIN_VERSION/bin \
    && tar -xzvf bitcoin.tar.gz $BD/bitcoind $BD/bitcoin-cli --strip-components=1

FROM ubuntu:16.04

RUN apt-get update && apt-get install -y --no-install-recommends socat libgmp-dev inotify-tools libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/* 

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_PORT=9835

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config
VOLUME [ "/root/.lightning" ]

COPY --from=builder /opt/lightningd/cli/lightning-cli /usr/bin
COPY --from=builder /opt/lightningd/lightningd/lightning* /usr/bin/
COPY --from=builder /opt/bitcoin/bin /usr/bin
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9112 9735 9835
ENTRYPOINT  [ "./entrypoint.sh" ]