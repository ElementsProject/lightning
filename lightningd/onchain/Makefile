#! /usr/bin/make

# Designed to be run one level up
lightningd/onchain-wrongdir:
	$(MAKE) -C ../.. lightningd/onchain-all

default: lightningd/onchain-all

lightningd/onchain-all: lightningd/lightningd_onchain

lightningd/onchain/gen_onchain_types_names.h: lightningd/onchain/onchain_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr lightningd/onchain/onchain_types.h > $@

# lightningd/onchain needs these:
LIGHTNINGD_ONCHAIN_HEADERS_GEN :=			\
	lightningd/onchain/gen_onchain_wire.h		\
	lightningd/onchain/gen_onchain_types_names.h

LIGHTNINGD_ONCHAIN_HEADERS_NOGEN :=			\
	lightningd/onchain/onchain_types.h		\
	lightningd/onchain/onchain_wire.h

LIGHTNINGD_ONCHAIN_HEADERS := $(LIGHTNINGD_ONCHAIN_HEADERS_GEN) $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN)

LIGHTNINGD_ONCHAIN_SRC := lightningd/onchain/onchain.c	\
	lightningd/onchain/gen_onchain_wire.c		\
	lightningd/onchain/onchain_wire.c

LIGHTNINGD_ONCHAIN_OBJS := $(LIGHTNINGD_ONCHAIN_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_ONCHAIN_CONTROL_HEADERS :=			\
	lightningd/onchain/gen_onchain_wire.h		\
	lightningd/onchain/onchain_wire.h
LIGHTNINGD_ONCHAIN_CONTROL_SRC := $(LIGHTNINGD_ONCHAIN_CONTROL_HEADERS:.h=.c)
LIGHTNINGD_ONCHAIN_CONTROL_OBJS := $(LIGHTNINGD_ONCHAIN_CONTROL_SRC:.c=.o)

LIGHTNINGD_ONCHAIN_GEN_SRC := $(filter lightningd/onchain/gen_%, $(LIGHTNINGD_ONCHAIN_SRC) $(LIGHTNINGD_ONCHAIN_CONTROL_SRC))

LIGHTNINGD_ONCHAIN_SRC_NOGEN := $(filter-out lightningd/onchain/gen_%, $(LIGHTNINGD_ONCHAIN_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_ONCHAIN_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN)

$(LIGHTNINGD_ONCHAIN_OBJS): $(LIGHTNINGD_HEADERS)

# Common source we use.
ONCHAIND_COMMON_OBJS :=				\
	common/daemon_conn.o			\
	common/debug.o				\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/htlc_tx.o			\
	common/htlc_wire.o			\
	common/initial_commit_tx.o		\
	common/keyset.o				\
	common/key_derive.o			\
	common/msg_queue.o			\
	common/permute_tx.o			\
	common/status.o				\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o

lightningd/onchain/gen_onchain_wire.h: $(WIRE_GEN) lightningd/onchain/onchain_wire.csv
	$(WIRE_GEN) --header $@ onchain_wire_type < lightningd/onchain/onchain_wire.csv > $@

lightningd/onchain/gen_onchain_wire.c: $(WIRE_GEN) lightningd/onchain/onchain_wire.csv
	$(WIRE_GEN) ${@:.c=.h} onchain_wire_type < lightningd/onchain/onchain_wire.csv > $@

LIGHTNINGD_ONCHAIN_OBJS := $(LIGHTNINGD_ONCHAIN_SRC:.c=.o) $(LIGHTNINGD_ONCHAIN_GEN_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_ONCHAIN_OBJS)

lightningd/lightningd_onchain: $(LIGHTNINGD_ONCHAIN_OBJS) $(WIRE_ONION_OBJS) $(ONCHAIND_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS)

check-source: $(LIGHTNINGD_ONCHAIN_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_ONCHAIN_SRC:%=bolt-check/%) $(LIGHTNINGD_ONCHAIN_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_ONCHAIN_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/onchain-clean

lightningd/onchain-clean:
	$(RM) $(LIGHTNINGD_ONCHAIN_OBJS) gen_*

-include lightningd/onchain/test/Makefile 
