#! /usr/bin/make

# Designed to be run one level up
gossipd-wrongdir:
	$(MAKE) -C .. gossipd-all

default: gossipd-all

# lightningd uses this:
LIGHTNINGD_GOSSIP_CONTROL_HEADERS := gossipd/gossipd_wiregen.h
LIGHTNINGD_GOSSIP_CONTROL_SRC := gossipd/gossipd_wiregen.c
LIGHTNINGD_GOSSIP_CONTROL_OBJS := $(LIGHTNINGD_GOSSIP_CONTROL_SRC:.c=.o)

# gossipd needs these:
LIGHTNINGD_GOSSIP_HEADERS_WSRC := gossipd/gossipd_wiregen.h \
	gossipd/gossipd_peerd_wiregen.h			\
	gossipd/gossip_store_wiregen.h			\
	gossipd/gossipd.h				\
	gossipd/gossip_store.h				\
	gossipd/queries.h				\
	gossipd/gossip_generation.h			\
	gossipd/routing.h				\
	gossipd/seeker.h
LIGHTNINGD_GOSSIP_HEADERS := $(LIGHTNINGD_GOSSIP_HEADERS_WSRC) gossipd/broadcast.h
LIGHTNINGD_GOSSIP_SRC := $(LIGHTNINGD_GOSSIP_HEADERS_WSRC:.h=.c)
LIGHTNINGD_GOSSIP_OBJS := $(LIGHTNINGD_GOSSIP_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_GOSSIP_OBJS)
ALL_PROGRAMS += lightningd/lightning_gossipd
ALL_GEN_HEADERS += $(wildcard gossipd/*wiregen.h)

# For checking
LIGHTNINGD_GOSSIP_ALLSRC_NOGEN := $(filter-out gossipd/%wiregen.c, $(LIGHTNINGD_GOSSIP_CLIENT_SRC) $(LIGHTNINGD_GOSSIP_SRC))
LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN := $(filter-out gossipd/%wiregen.h, $(LIGHTNINGD_GOSSIP_CLIENT_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_GOSSIP_HEADERS)

# Common source we use.
GOSSIPD_COMMON_OBJS :=				\
	bitcoin/chainparams.o			\
	common/amount.o				\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bip32.o				\
	common/channel_id.o			\
	common/crypto_state.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/decode_array.o			\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/features.o			\
	common/status_wiregen.o			\
	common/gossip_rcvd_filter.o		\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/per_peer_state.o			\
	common/ping.o				\
	common/pseudorand.o			\
	common/setup.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wireaddr.o			\
	common/wire_error.o			\
	connectd/connectd_gossipd_wiregen.o	\
	lightningd/gossip_msg.o			\
	wire/gen_onion_wire.o

$(LIGHTNINGD_GOSSIP_OBJS) $(LIGHTNINGD_GOSSIP_CLIENT_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS)

$(LIGHTNINGD_GOSSIP_CONTROL_OBJS) : $(LIGHTNINGD_GOSSIP_CONTROL_HEADERS)

gossipd-all: lightningd/lightning_gossipd $(LIGHTNINGD_GOSSIP_CLIENT_OBJS)

lightningd/lightning_gossipd: $(LIGHTNINGD_GOSSIP_OBJS) $(GOSSIPD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

check-source: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_GOSSIP_SRC:%=bolt-check/%) $(LIGHTNINGD_GOSSIP_HEADERS:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: gossipd-clean

gossipd-clean:
	$(RM) $(LIGHTNINGD_GOSSIP_OBJS)

-include gossipd/test/Makefile
