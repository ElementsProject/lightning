#! /usr/bin/make

# Designed to be run one level up
lightningd/channel-wrongdir:
	$(MAKE) -C ../.. lightningd/channel-all

default: lightningd/channel-all

lightningd/channel-all: lightningd/lightningd_channel

# lightningd/channel needs these:
LIGHTNINGD_CHANNEL_HEADERS_GEN :=			\
	lightningd/channel/gen_channel_wire.h

LIGHTNINGD_CHANNEL_HEADERS_NOGEN :=			\
	lightningd/channel/channeld_htlc.h		\
	lightningd/channel/commit_tx.h			\
	lightningd/channel/full_channel.h

LIGHTNINGD_CHANNEL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS_GEN) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

LIGHTNINGD_CHANNEL_SRC := lightningd/channel/channel.c	\
	lightningd/channel/commit_tx.c			\
	lightningd/channel/full_channel.c		\
	$(LIGHTNINGD_CHANNEL_HEADERS_GEN:.h=.c)
LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_CHANNEL_OBJS)

# Common source we use.
CHANNELD_COMMON_OBJS :=				\
	common/channel_config.o			\
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
	common/version.o

# Control daemon uses this:
LIGHTNINGD_CHANNEL_CONTROL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS_GEN)
LIGHTNINGD_CHANNEL_CONTROL_SRC := $(LIGHTNINGD_CHANNEL_HEADERS_GEN:.h=.c)
LIGHTNINGD_CHANNEL_CONTROL_OBJS := $(LIGHTNINGD_CHANNEL_CONTROL_SRC:.c=.o)

LIGHTNINGD_CHANNEL_GEN_SRC := $(filter lightningd/channel/gen_%, $(LIGHTNINGD_CHANNEL_SRC) $(LIGHTNINGD_CHANNEL_CONTROL_SRC))

LIGHTNINGD_CHANNEL_SRC_NOGEN := $(filter-out lightningd/channel/gen_%, $(LIGHTNINGD_CHANNEL_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_CHANNEL_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

$(LIGHTNINGD_CHANNEL_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/channel/gen_channel_wire.h: $(WIRE_GEN) lightningd/channel/channel_wire.csv
	$(WIRE_GEN) --header $@ channel_wire_type < lightningd/channel/channel_wire.csv > $@

lightningd/channel/gen_channel_wire.c: $(WIRE_GEN) lightningd/channel/channel_wire.csv
	$(WIRE_GEN) ${@:.c=.h} channel_wire_type < lightningd/channel/channel_wire.csv > $@

LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o) $(LIGHTNINGD_CHANNEL_GEN_SRC:.c=.o)

lightningd/lightningd_channel: $(LIGHTNINGD_CHANNEL_OBJS) $(WIRE_ONION_OBJS) $(CHANNELD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

check-source: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_CHANNEL_SRC:%=bolt-check/%) $(LIGHTNINGD_CHANNEL_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/channel-clean

lightningd/channel-clean:
	$(RM) $(LIGHTNINGD_CHANNEL_OBJS) gen_*

-include lightningd/channel/test/Makefile 
