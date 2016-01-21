#! /usr/bin/make

# Designed to be run one level up
daemon-wrongdir:
	$(MAKE) -C .. daemon-all

daemon-all: daemon/lightningd

DAEMON_SRC :=					\
	daemon/configdir.c			\
	daemon/lightningd.c			\
	daemon/log.c				\
	daemon/pseudorand.c
DAEMON_OBJS := $(DAEMON_SRC:.c=.o)

DAEMON_HEADERS :=				\
	daemon/configdir.h			\
	daemon/lightningd.h			\
	daemon/log.h				\
	daemon/pseudorand.h

$(DAEMON_OBJS): $(DAEMON_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(CCAN_HEADERS)

check-source: $(DAEMON_SRC:%=check-src-include-order/%)
check-source: $(DAEMON_HEADERS:%=check-hdr-include-order/%)
check-daemon-makefile:
	@if [ "`echo daemon/*.h`" != "$(DAEMON_HEADERS)" ]; then echo DAEMON_HEADERS incorrect; exit 1; fi

daemon/lightningd: $(DAEMON_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) libsecp256k1.a
