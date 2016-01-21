#! /usr/bin/make

# Designed to be run one level up
daemon-wrongdir:
	$(MAKE) -C .. daemon-all

daemon-all: daemon/lightningd

DAEMON_SRC :=					\
	daemon/lightningd.c			\
	daemon/log.c				\
	daemon/pseudorand.c
DAEMON_OBJS := $(DAEMON_SRC:.c=.o)

DAEMON_HEADERS :=				\
	daemon/lightningd.h			\
	daemon/log.h				\
	daemon/pseudorand.h

$(DAEMON_OBJS): $(DAEMON_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(CCAN_HEADERS)

check-source: $(DAEMON_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_HEADERS:%=check-hdr-include-order/%)

daemon/lightningd: $(DAEMON_OBJS) $(CCAN_OBJS)
