#!/bin/bash

# This build script is for running the Travis builds using docker.
# Stolen from: https://github.com/shenki/openbmc-build-scripts/blob/master/linux-openbmc-build.sh

# Trace bash processing
set -ex

# Build the docker container
docker build -t ubuntu - <<EOF
FROM ubuntu:16.10

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
	apt-get install -yy eatmydata software-properties-common && \
	eatmydata add-apt-repository -y ppa:bitcoin/bitcoin && \
	eatmydata apt-get update && \
	eatmydata apt-get install -yy \
	build-essential autoconf libtool libprotobuf-c-dev libsqlite3-dev libgmp-dev libsqlite3-dev git python3 python valgrind net-tools bitcoind python3-pip && \
	pip3 install python-bitcoinlib

RUN grep -q ${GROUPS} /etc/group || groupadd -g ${GROUPS} ${USER}
RUN grep -q ${UID} /etc/passwd || useradd -d ${HOME} -m -u ${UID} -g ${GROUPS} ${USER}

USER ${USER}
ENV HOME ${HOME}
RUN /bin/bash
EOF

# Run the docker container, execute the build script we just built
docker run --rm=true --user="${USER}" -w "$TRAVIS_BUILD_DIR" -v "${HOME}":"${HOME}" \
       -t ubuntu make -j2 check-source check
