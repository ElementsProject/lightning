FROM alpine:3.7 as builder

RUN apk add --no-cache \
     ca-certificates \
     autoconf \
     automake \
     build-base \
     libressl \
     libtool \
     gmp-dev \
     python \
     python-dev \
     python3 \
     sqlite-dev \
     wget \
     git \
     file \
     gnupg \
     swig \
     zlib-dev

WORKDIR /opt

ARG BITCOIN_VERSION=0.17.0
ENV BITCOIN_TARBALL bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz
ENV BITCOIN_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/$BITCOIN_TARBALL
ENV BITCOIN_ASC_URL https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/SHA256SUMS.asc
ENV BITCOIN_PGP_KEY 01EA5486DE18A882D4C2684590C8019E36C2E964

RUN mkdir /opt/bitcoin && cd /opt/bitcoin \
    && wget -qO $BITCOIN_TARBALL "$BITCOIN_URL" \
    && gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "$BITCOIN_PGP_KEY" \
    && wget -qO bitcoin.asc "$BITCOIN_ASC_URL" \
    && gpg --verify bitcoin.asc \
    && grep $BITCOIN_TARBALL bitcoin.asc | tee SHA256SUMS.asc \
    && sha256sum -c SHA256SUMS.asc \
    && BD=bitcoin-$BITCOIN_VERSION/bin \
    && tar -xzvf $BITCOIN_TARBALL $BD/bitcoin-cli --strip-components=1 \
    && rm $BITCOIN_TARBALL

ENV LITECOIN_VERSION 0.16.3
ENV LITECOIN_PGP_KEY FE3348877809386C
ENV LITECOIN_URL https://download.litecoin.org/litecoin-${LITECOIN_VERSION}/linux/litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz
ENV LITECOIN_ASC_URL https://download.litecoin.org/litecoin-${LITECOIN_VERSION}/linux/litecoin-${LITECOIN_VERSION}-linux-signatures.asc

# install litecoin binaries
RUN mkdir /opt/litecoin && cd /opt/litecoin \
    && wget -qO litecoin.tar.gz "$LITECOIN_URL" \
    && gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "$LITECOIN_PGP_KEY" \
    && wget -qO litecoin.asc "$LITECOIN_ASC_URL" \
    && gpg --verify litecoin.asc \
    && BD=litecoin-$LITECOIN_VERSION/bin \
    && tar -xzvf litecoin.tar.gz $BD/litecoin-cli --strip-components=1 --exclude=*-qt \
    && rm litecoin.tar.gz

ENV LIGHTNINGD_VERSION=master

WORKDIR /opt/lightningd
COPY . .

ARG DEVELOPER=0
RUN ./configure && make -j3 DEVELOPER=${DEVELOPER} && cp lightningd/lightning* cli/lightning-cli /usr/bin/

FROM microsoft/dotnet:2.1.403-sdk-alpine3.7 AS dotnetbuilder

RUN apk add --no-cache git

WORKDIR /source

RUN git clone https://github.com/dgarage/NBXplorer && cd NBXplorer && git checkout 88a8db8be3911f59b4b6109845b547368c5f02fb

# Cache some dependencies
RUN cd NBXplorer/NBXplorer.NodeWaiter && dotnet restore && cd ..
RUN cd NBXplorer/NBXplorer.NodeWaiter && \
    dotnet publish --output /app/ --configuration Release

FROM microsoft/dotnet:2.1.5-runtime-alpine3.7

RUN apk add --no-cache \
     gmp-dev \
     sqlite-dev \
     inotify-tools \
     socat \
     bash \
     zlib-dev

ARG TRACE_TOOLS=false
ENV TRACE_TOOLS=$TRACE_TOOLS

ENV GLIBC_VERSION 2.27-r0
ENV GLIBC_SHA256 938bceae3b83c53e7fa9cc4135ce45e04aae99256c5e74cf186c794b97473bc7
ENV GLIBCBIN_SHA256 3a87874e57b9d92e223f3e90356aaea994af67fb76b71bb72abfb809e948d0d6

ENV TRACE_LOCATION=/opt/traces
VOLUME /opt/traces

# Download and install glibc (https://github.com/jeanblanchard/docker-alpine-glibc/blob/master/Dockerfile)
RUN apk add --update curl && \
  curl -Lo /etc/apk/keys/sgerrand.rsa.pub https://github.com/sgerrand/alpine-pkg-glibc/releases/download/$GLIBC_VERSION/sgerrand.rsa.pub && \
  curl -Lo glibc.apk "https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-${GLIBC_VERSION}.apk" && \
  echo "$GLIBC_SHA256  glibc.apk" | sha256sum -c - && \
  curl -Lo glibc-bin.apk "https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-bin-${GLIBC_VERSION}.apk" && \
  echo "$GLIBCBIN_SHA256  glibc-bin.apk" | sha256sum -c - && \
  apk add glibc-bin.apk glibc.apk && \
  /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc-compat/lib && \
  echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf && \
  ( ! $TRACE_TOOLS || \
    ( \
        sed -i -e 's/v[[:digit:]]\.[[:digit:]]/edge/g' /etc/apk/repositories && \
        echo "http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
        apk add --no-cache perf perl && \
        mkdir FlameGraph && cd FlameGraph && \
        curl -Lo FlameGraph.tar.gz "https://github.com/brendangregg/FlameGraph/archive/v1.0.tar.gz" && \
        tar -zxvf FlameGraph.tar.gz --strip-components=1 && rm FlameGraph.tar.gz && cd .. \
    ) \
  ) && \
  apk del curl && \
  rm -rf glibc.apk glibc-bin.apk /var/cache/apk/*

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config

VOLUME [ "/root/.lightning" ]

COPY --from=builder /opt/lightningd/cli/lightning-cli /usr/bin
COPY --from=builder /opt/lightningd/lightningd/lightning* /usr/bin/
COPY --from=builder /opt/bitcoin/bin /usr/bin
COPY --from=builder /opt/litecoin/bin /usr/bin
COPY --from=dotnetbuilder /app /opt/NBXplorer.NodeWaiter
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "./entrypoint.sh" ]
