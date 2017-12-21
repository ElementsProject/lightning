FROM ubuntu:16.04
MAINTAINER Christian Decker <decker.christian@gmail.com>

ENV DEBIAN_FRONTEND noninteractive
WORKDIR /build

RUN apt-get -qq update && \
    apt-get -qq install --no-install-recommends --allow-unauthenticated -yy \
	autoconf \
	automake \
	clang \
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
	python3-pip \
	python3-setuptools \
	python-pkg-resources \
	wget && \
	rm -rf /var/lib/apt/lists/*

RUN cd /tmp/ && \
    wget https://bitcoin.org/bin/bitcoin-core-0.15.0.1/bitcoin-0.15.0.1-x86_64-linux-gnu.tar.gz -O bitcoin.tar.gz && \
    tar -xvzf bitcoin.tar.gz && \
    mv /tmp/bitcoin-0.15.0/bin/bitcoin* /usr/local/bin/ && \
    rm -rf bitcoin.tar.gz /tmp/bitcoin-0.15.0

RUN pip3 install python-bitcoinlib==0.7.0 pytest==3.0.5 setuptools==36.6.0 pytest-test-groups==1.0.3
