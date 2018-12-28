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

FROM alpine:3.7

RUN apk add --no-cache \
     gmp-dev \
     sqlite-dev \
     inotify-tools \
     socat \
     bash \
     zlib-dev

ENV GLIBC_VERSION 2.27-r0
ENV GLIBC_SHA256 938bceae3b83c53e7fa9cc4135ce45e04aae99256c5e74cf186c794b97473bc7
ENV GLIBCBIN_SHA256 3a87874e57b9d92e223f3e90356aaea994af67fb76b71bb72abfb809e948d0d6
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
  apk del curl && \
  rm -rf glibc.apk glibc-bin.apk /var/cache/apk/*

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835

VOLUME [ "/root/.lightning" ]

COPY --from=builder /opt/lightningd/cli/lightning-cli /usr/bin
COPY --from=builder /opt/lightningd/lightningd/lightning* /usr/bin/
COPY --from=builder /opt/bitcoin/bin /usr/bin
COPY --from=builder /opt/litecoin/bin /usr/bin
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "./entrypoint.sh" ]
