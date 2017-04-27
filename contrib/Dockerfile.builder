FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive
WORKDIR /build

RUN echo "deb http://ppa.launchpad.net/bitcoin/bitcoin/ubuntu xenial main" | tee -a /etc/apt/sources.list.d/bitcoin.list
RUN apt-get -qq update && \
    apt-get -qq install --allow-unauthenticated -yy \
        eatmydata \
	software-properties-common \
	build-essential \
	autoconf \
	libtool \
	libprotobuf-c-dev \
	libsqlite3-dev \
	libgmp-dev \
	libsqlite3-dev \
	git \
	python \
	python3 \
	valgrind \
	net-tools \
	bitcoind \
	python3-pip \
	&& rm -rf /var/lib/apt/lists/*

RUN pip3 install python-bitcoinlib==0.7.0
