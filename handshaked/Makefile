#! /usr/bin/make

# Designed to be run one level up
handshaked-wrongdir:
	$(MAKE) -C .. handshaked-all

default: handshaked-all

handshaked-all: lightningd/lightning_handshaked

# handshaked needs these:
LIGHTNINGD_HANDSHAKE_HEADERS :=					\
	handshaked/gen_handshake_wire.h
LIGHTNINGD_HANDSHAKE_SRC := handshaked/handshake.c	\
	$(LIGHTNINGD_HANDSHAKE_HEADERS:.h=.c)
LIGHTNINGD_HANDSHAKE_OBJS := $(LIGHTNINGD_HANDSHAKE_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_HANDSHAKE_OBJS)
ALL_PROGRAMS += lightningd/lightning_handshaked
ALL_GEN_HEADERS += $(LIGHTNINGD_HANDSHAKE_HEADERS)

# Control daemon uses this:
LIGHTNINGD_HANDSHAKE_CONTROL_HEADERS := $(LIGHTNINGD_HANDSHAKE_HEADERS)
LIGHTNINGD_HANDSHAKE_CONTROL_SRC := $(LIGHTNINGD_HANDSHAKE_HEADERS:.h=.c)
LIGHTNINGD_HANDSHAKE_CONTROL_OBJS := $(LIGHTNINGD_HANDSHAKE_CONTROL_SRC:.c=.o)

LIGHTNINGD_HANDSHAKE_GEN_SRC := $(filter handshaked/gen_%, $(LIGHTNINGD_HANDSHAKE_SRC) $(LIGHTNINGD_HANDSHAKE_CONTROL_SRC))

LIGHTNINGD_HANDSHAKE_SRC_NOGEN := $(filter-out handshaked/gen_%, $(LIGHTNINGD_HANDSHAKE_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_HANDSHAKE_HEADERS)

$(LIGHTNINGD_HANDSHAKE_OBJS): $(LIGHTNINGD_HEADERS)

# Common source we use.
HANDSHAKED_COMMON_OBJS :=			\
	common/crypto_sync.o			\
	common/cryptomsg.o			\
	common/daemon_conn.o			\
	common/debug.o				\
	common/dev_disconnect.o			\
	common/msg_queue.o			\
	common/status.o				\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o

handshaked/gen_handshake_wire.h: $(WIRE_GEN) handshaked/handshake_wire.csv
	$(WIRE_GEN) --header $@ handshake_wire_type < handshaked/handshake_wire.csv > $@

handshaked/gen_handshake_wire.c: $(WIRE_GEN) handshaked/handshake_wire.csv
	$(WIRE_GEN) ${@:.c=.h} handshake_wire_type < handshaked/handshake_wire.csv > $@

LIGHTNINGD_HANDSHAKE_OBJS := $(LIGHTNINGD_HANDSHAKE_SRC:.c=.o) $(LIGHTNINGD_HANDSHAKE_GEN_SRC:.c=.o)

lightningd/lightning_handshaked: $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_HANDSHAKE_OBJS) $(HANDSHAKED_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

check-source: $(LIGHTNINGD_HANDSHAKE_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_HANDSHAKE_SRC:%=bolt-check/%) $(LIGHTNINGD_HANDSHAKE_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HANDSHAKE_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HANDSHAKE_HEADERS_NOGEN:%=check-whitespace/%)

clean: handshaked-clean

handshaked-clean:
	$(RM) $(LIGHTNINGD_HANDSHAKE_OBJS) gen_*

-include handshaked/test/Makefile 
