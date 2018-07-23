#! /usr/bin/make

# Designed to be run one level up
onchaind-wrongdir:
	$(MAKE) -C ../.. onchaind-all

default: onchaind-all

onchaind-all: lightningd/lightning_onchaind

onchaind/gen_onchain_types_names.h: onchaind/onchain_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr onchaind/onchain_types.h > $@

# onchaind needs these:
LIGHTNINGD_ONCHAIN_HEADERS_GEN :=			\
	onchaind/gen_onchain_wire.h		\
	onchaind/gen_onchain_types_names.h

LIGHTNINGD_ONCHAIN_HEADERS_NOGEN :=			\
	onchaind/onchain_types.h		\
	onchaind/onchain_wire.h

LIGHTNINGD_ONCHAIN_HEADERS := $(LIGHTNINGD_ONCHAIN_HEADERS_GEN) $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN)

LIGHTNINGD_ONCHAIN_SRC := onchaind/onchain.c	\
	onchaind/gen_onchain_wire.c		\
	onchaind/onchain_wire.c

LIGHTNINGD_ONCHAIN_OBJS := $(LIGHTNINGD_ONCHAIN_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_ONCHAIN_CONTROL_HEADERS :=			\
	onchaind/gen_onchain_wire.h		\
	onchaind/onchain_wire.h
LIGHTNINGD_ONCHAIN_CONTROL_SRC := $(LIGHTNINGD_ONCHAIN_CONTROL_HEADERS:.h=.c)
LIGHTNINGD_ONCHAIN_CONTROL_OBJS := $(LIGHTNINGD_ONCHAIN_CONTROL_SRC:.c=.o)

LIGHTNINGD_ONCHAIN_GEN_SRC := $(filter onchaind/gen_%, $(LIGHTNINGD_ONCHAIN_SRC) $(LIGHTNINGD_ONCHAIN_CONTROL_SRC))

LIGHTNINGD_ONCHAIN_SRC_NOGEN := $(filter-out onchaind/gen_%, $(LIGHTNINGD_ONCHAIN_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_ONCHAIN_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN)

$(LIGHTNINGD_ONCHAIN_OBJS): $(LIGHTNINGD_HEADERS)

# Common source we use.
ONCHAIND_COMMON_OBJS :=				\
	common/bip32.o				\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/gen_status_wire.o		\
	common/htlc_tx.o			\
	common/htlc_wire.o			\
	common/initial_commit_tx.o		\
	common/keyset.o				\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/peer_billboard.o			\
	common/permute_tx.o			\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o

onchaind/gen_onchain_wire.h: $(WIRE_GEN) onchaind/onchain_wire.csv
	$(WIRE_GEN) --header $@ onchain_wire_type < onchaind/onchain_wire.csv > $@

onchaind/gen_onchain_wire.c: $(WIRE_GEN) onchaind/onchain_wire.csv
	$(WIRE_GEN) ${@:.c=.h} onchain_wire_type < onchaind/onchain_wire.csv > $@

LIGHTNINGD_ONCHAIN_OBJS := $(LIGHTNINGD_ONCHAIN_SRC:.c=.o) $(LIGHTNINGD_ONCHAIN_GEN_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_ONCHAIN_OBJS)
ALL_PROGRAMS += lightningd/lightning_onchaind
ALL_GEN_HEADERS += $(LIGHTNINGD_ONCHAIN_HEADERS_GEN)

lightningd/lightning_onchaind: $(LIGHTNINGD_ONCHAIN_OBJS) $(WIRE_ONION_OBJS) $(ONCHAIND_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

check-source: $(LIGHTNINGD_ONCHAIN_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_ONCHAIN_SRC:%=bolt-check/%) $(LIGHTNINGD_ONCHAIN_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_ONCHAIN_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_ONCHAIN_HEADERS_NOGEN:%=check-whitespace/%)

clean: onchaind-clean

onchaind-clean:
	$(RM) $(LIGHTNINGD_ONCHAIN_OBJS) onchaind/gen_*

-include onchaind/test/Makefile
