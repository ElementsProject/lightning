#! /usr/bin/make

# Designed to be run one level up
gossipd-wrongdir:
	$(MAKE) -C .. gossipd-all

default: gossipd-all

# lightningd uses this:
LIGHTNINGD_GOSSIP_CONTROL_HEADERS := gossipd/gen_gossip_wire.h
LIGHTNINGD_GOSSIP_CONTROL_SRC := gossipd/gen_gossip_wire.c
LIGHTNINGD_GOSSIP_CONTROL_OBJS := $(LIGHTNINGD_GOSSIP_CONTROL_SRC:.c=.o)

# gossipd needs these:
LIGHTNINGD_GOSSIP_HEADERS_WSRC := gossipd/gen_gossip_wire.h \
	gossipd/gen_gossip_peerd_wire.h \
	gossipd/gen_gossip_store.h			\
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
ALL_GEN_HEADERS += gossipd/gen_gossip_wire.h gossipd/gen_gossip_peerd_wire.h

# For checking
LIGHTNINGD_GOSSIP_ALLSRC_NOGEN := $(filter-out gossipd/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_SRC) $(LIGHTNINGD_GOSSIP_SRC))
LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN := $(filter-out gossipd/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS))

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
	common/gen_status_wire.o		\
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
	connectd/gen_connect_gossip_wire.o	\
	lightningd/gossip_msg.o			\
	wire/gen_onion_wire.o

$(LIGHTNINGD_GOSSIP_OBJS) $(LIGHTNINGD_GOSSIP_CLIENT_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS)

$(LIGHTNINGD_GOSSIP_CONTROL_OBJS) : $(LIGHTNINGD_GOSSIP_CONTROL_HEADERS)

gossipd-all: lightningd/lightning_gossipd $(LIGHTNINGD_GOSSIP_CLIENT_OBJS)

lightningd/lightning_gossipd: $(LIGHTNINGD_GOSSIP_OBJS) $(GOSSIPD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

gossipd/gen_gossip_wire.h: $(WIRE_GEN) gossipd/gossip_wire.csv
	$(WIRE_GEN) --page header $@ gossip_wire_type < gossipd/gossip_wire.csv > $@

gossipd/gen_gossip_wire.c: $(WIRE_GEN) gossipd/gossip_wire.csv
	$(WIRE_GEN) --page impl ${@:.c=.h} gossip_wire_type < gossipd/gossip_wire.csv > $@

gossipd/gen_gossip_peerd_wire.h: $(WIRE_GEN) gossipd/gossip_peerd_wire.csv
	$(WIRE_GEN) --page header $@ gossip_peerd_wire_type < gossipd/gossip_peerd_wire.csv > $@

gossipd/gen_gossip_peerd_wire.c: $(WIRE_GEN) gossipd/gossip_peerd_wire.csv
	$(WIRE_GEN) --page impl ${@:.c=.h} gossip_peerd_wire_type < gossipd/gossip_peerd_wire.csv > $@

gossipd/gen_gossip_store.h: $(WIRE_GEN) gossipd/gossip_store.csv
	$(WIRE_GEN) --page header $@ gossip_store_type < gossipd/gossip_store.csv > $@

gossipd/gen_gossip_store.c: $(WIRE_GEN) gossipd/gossip_store.csv
	$(WIRE_GEN) --page impl ${@:.c=.h} gossip_store_type < gossipd/gossip_store.csv > $@


check-source: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_GOSSIP_SRC:%=bolt-check/%) $(LIGHTNINGD_GOSSIP_HEADERS:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: gossipd-clean

gossipd-clean:
	$(RM) $(LIGHTNINGD_GOSSIP_OBJS) gossipd/gen_*

-include gossipd/test/Makefile
