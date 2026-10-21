# syntax=docker/dockerfile:1.7
# The runtime image: it consumes a release tarball and compiles nothing.
#
# A thin wrapper around signed release artifacts: it never compiles and,
# apart from the single apt-get below, never touches the network.  Built by
# `tools/reprobuild docker` (multi-platform, docker-container builder,
# output = OCI layout dir), which passes three named build contexts:
#
#   release   clightning-${VERSION}-static-{amd64,arm64,armhf}.tar.xz
#             (the signed static tarballs, --prefix=/usr layout)
#   bitcoin   <triplet>/bin/bitcoin-cli, pre-verified by `tools/reprobuild fetch`
#   vls       remote_hsmd_socket-${VLS_VERSION}-{amd64,arm64,armhf}
#
# and the build args VERSION, VLS_VERSION, SOURCE_DATE_EPOCH, CREATED, REVISION.
# The main context only supplies tools/docker-entrypoint.sh (see .dockerignore).

# Base pinned by index digest; bumped deliberately, like a package pin.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS base

# --- arch selector: Docker's TARGETARCH -> the matrix's arch token and the
#     Bitcoin Core release triplet.  ARGs propagate to the derived stages.
FROM base AS arch-linux-amd64
ARG cl_arch=amd64
ARG bitcoin_triplet=x86_64-linux-gnu

FROM base AS arch-linux-arm64
ARG cl_arch=arm64
ARG bitcoin_triplet=aarch64-linux-gnu

FROM base AS arch-linux-arm
ARG cl_arch=armhf
ARG bitcoin_triplet=arm-linux-gnueabihf

# --- lightningd: the published image
FROM arch-${TARGETOS}-${TARGETARCH} AS lightningd
ARG VERSION
ARG CREATED
ARG REVISION

# The one unpinned, network-touching input: the entrypoint's
# runtime deps plus xz-utils (trixie-slim has no xz, the tarball needs it).
# Everything apt leaves behind that is not package content is
# removed so the layer depends on the package set only.
RUN apt-get update && \
    apt-get install -y --no-install-recommends bash inotify-tools socat jq xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log \
        /var/log/alternatives.log /var/cache/ldconfig/aux-cache

COPY --from=bitcoin ${bitcoin_triplet}/bin/bitcoin-cli /usr/bin/bitcoin-cli

# The tarball unpacks straight onto / (its layout is /usr/...); mounting it
# keeps the archive itself out of the image.
RUN --mount=from=release,source=clightning-${VERSION}-static-${cl_arch}.tar.xz,target=/tmp/cln.tar.xz \
    tar -xJf /tmp/cln.tar.xz -C /

COPY tools/docker-entrypoint.sh /entrypoint.sh

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_RPC_PORT=9835
ENV LIGHTNINGD_PORT=9735
ENV LIGHTNINGD_NETWORK=bitcoin

LABEL org.opencontainers.image.title="Core Lightning" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/ElementsProject/lightning" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-slim"

EXPOSE 9735 9835
VOLUME ["/root/.lightning"]
ENTRYPOINT ["/entrypoint.sh"]

# --- lightningd-vls: one overlay layer on lightningd
FROM lightningd AS lightningd-vls
ARG VERSION
ARG VLS_VERSION
COPY --from=vls remote_hsmd_socket-${VLS_VERSION}-${cl_arch} /var/lib/vls/bin/remote_hsmd_socket
# remote_hsmd_socket compares this byte-for-byte with lightningd --version.
ENV VLS_CLN_VERSION=${VERSION}
ENV VLS_ENABLED=true
