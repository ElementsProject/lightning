#! /usr/bin/make

# Designed to be run one level up
lightningd-wrongdir:
	$(MAKE) -C .. lightningd-all

lightningd-all: lightningd/lightningd lightningd/lightningd_hsm lightningd/lightningd_handshake

default: lightningd-all

LIGHTNINGD_OLD_SRC :=				\
	daemon/configdir.c			\
	daemon/json.c				\
	daemon/jsonrpc.c			\
	daemon/log.c				\
	daemon/options.c			\
	daemon/opt_time.c			\
	daemon/pseudorand.c			\
	daemon/routing.c			\
	daemon/timeout.c			\
	daemon/watch.c
LIGHTNINGD_OLD_OBJS := $(LIGHTNINGD_OLD_SRC:.c=.o)
LIGHTNINGD_OLD_HEADERS := $(LIGHTNINGD_OLD_SRC:.c=.h)

LIGHTNINGD_LIB_SRC :=				\
	lightningd/cryptomsg.c

LIGHTNINGD_LIB_OBJS := $(LIGHTNINGD_LIB_SRC:.c=.o)
LIGHTNINGD_LIB_HEADERS := $(LIGHTNINGD_LIB_SRC:.c=.h)

LIGHTNINGD_SRC :=				\
	lightningd/hsm_control.c		\
	lightningd/lightningd.c			\
	lightningd/peer_control.c		\
	lightningd/subdaemon.c

LIGHTNINGD_OBJS := $(LIGHTNINGD_SRC:.c=.o)

LIGHTNINGD_JSMN_OBJS := daemon/jsmn.o
LIGHTNINGD_JSMN_HEADERS := daemon/jsmn/jsmn.h

LIGHTNINGD_HEADERS :=				\
	lightningd/hsm_control.h		\
	lightningd/lightningd.h			\
	lightningd/peer_control.h		\
	lightningd/subdaemon.h

$(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_JSMN_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(CCAN_HEADERS) $(DAEMON_HEADERS) $(LIGHTNINGD_HSM_CONTROL_HEADERS) $(LIGHTNINGD_HANDSHAKE_CONTROL_HEADERS) $(LIBBASE58_HEADERS)

include lightningd/hsm/Makefile
include lightningd/handshake/Makefile

check-source: $(LIGHTNINGD_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_LIB_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_CLI_SRC:%=check-src-include-order/%)
check-source: $(LIGHTNINGD_HEADERS:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_SRC:%=bolt-check/%) $(LIGHTNINGD_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_SRC:%=check-whitespace/%) $(LIGHTNINGD_HEADERS:%=check-whitespace/%) $(LIGHTNINGD_LIB_SRC:%=check-whitespace/%) $(LIGHTNINGD_LIB_HEADERS:%=check-whitespace/%)

check-lightningd-makefile:
	@if [ "`ls lightningd/*.h | grep -v lightningd/gen | tr '\012' ' '`" != "`echo $(LIGHTNINGD_HEADERS) ''`" ]; then echo LIGHTNINGD_HEADERS incorrect; exit 1; fi

lightningd/lightningd: $(LIGHTNINGD_OBJS) $(LIGHTNINGD_OLD_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_JSMN_OBJS) $(CORE_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) $(LIGHTNINGD_HSM_CONTROL_OBJS) $(LIGHTNINGD_HANDSHAKE_CONTROL_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a

clean: lightningd-clean

lightningd-clean:
	$(RM) $(LIGHTNINGD_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_JSMN_OBJS) 

include lightningd/test/Makefile
