#! /usr/bin/make

# Designed to be run one level up
channeld-wrongdir:
	$(MAKE) -C ../.. lightningd/channel-all

default: channeld-all

channeld-all: lightningd/lightning_channeld

# lightningd/channel needs these:
LIGHTNINGD_CHANNEL_HEADERS_GEN :=			\
	channeld/gen_channel_wire.h

LIGHTNINGD_CHANNEL_HEADERS_NOGEN :=			\
	channeld/channeld_htlc.h		\
	channeld/commit_tx.h			\
	channeld/full_channel.h

LIGHTNINGD_CHANNEL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS_GEN) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

LIGHTNINGD_CHANNEL_SRC := channeld/channel.c	\
	channeld/commit_tx.c			\
	channeld/full_channel.c		\
	$(LIGHTNINGD_CHANNEL_HEADERS_GEN:.h=.c)
LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_CHANNEL_OBJS)
ALL_PROGRAMS += lightningd/lightning_channeld
ALL_GEN_HEADERS += $(LIGHTNINGD_CHANNEL_HEADERS_GEN)

# Common source we use.
CHANNELD_COMMON_OBJS :=				\
	common/bip32.o			\
	common/channel_config.o			\
	common/crypto_state.o			\
	common/crypto_sync.o			\
	common/cryptomsg.o			\
	common/daemon_conn.o			\
	common/debug.o				\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/htlc_state.o			\
	common/htlc_tx.o			\
	common/htlc_wire.o			\
	common/initial_channel.o		\
	common/initial_commit_tx.o		\
	common/io_debug.o			\
	common/keyset.o				\
	common/key_derive.o			\
	common/msg_queue.o			\
	common/ping.o				\
	common/peer_failed.o			\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/sphinx.o				\
	common/status.o				\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	gossipd/gen_gossip_wire.o		\
	lightningd/gossip_msg.o			\
	wire/fromwire.o				\
	wire/towire.o

# Control daemon uses this:
LIGHTNINGD_CHANNEL_CONTROL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS_GEN)
LIGHTNINGD_CHANNEL_CONTROL_SRC := $(LIGHTNINGD_CHANNEL_HEADERS_GEN:.h=.c)
LIGHTNINGD_CHANNEL_CONTROL_OBJS := $(LIGHTNINGD_CHANNEL_CONTROL_SRC:.c=.o)

LIGHTNINGD_CHANNEL_GEN_SRC := $(filter channeld/gen_%, $(LIGHTNINGD_CHANNEL_SRC) $(LIGHTNINGD_CHANNEL_CONTROL_SRC))

LIGHTNINGD_CHANNEL_SRC_NOGEN := $(filter-out channeld/gen_%, $(LIGHTNINGD_CHANNEL_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_CHANNEL_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

$(LIGHTNINGD_CHANNEL_OBJS): $(LIGHTNINGD_HEADERS)

channeld/gen_channel_wire.h: $(WIRE_GEN) channeld/channel_wire.csv
	$(WIRE_GEN) --header $@ channel_wire_type < channeld/channel_wire.csv > $@

channeld/gen_channel_wire.c: $(WIRE_GEN) channeld/channel_wire.csv
	$(WIRE_GEN) ${@:.c=.h} channel_wire_type < channeld/channel_wire.csv > $@

LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o) $(LIGHTNINGD_CHANNEL_GEN_SRC:.c=.o)

lightningd/lightning_channeld: $(LIGHTNINGD_CHANNEL_OBJS) $(WIRE_ONION_OBJS) $(CHANNELD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

check-source: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_CHANNEL_SRC:%=bolt-check/%) $(LIGHTNINGD_CHANNEL_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/channel-clean

lightningd/channel-clean:
	$(RM) $(LIGHTNINGD_CHANNEL_OBJS) channeld/gen_*

-include channeld/test/Makefile
