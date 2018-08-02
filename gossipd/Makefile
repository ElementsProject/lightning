#! /usr/bin/make

# Designed to be run one level up
gossipd-wrongdir:
	$(MAKE) -C .. gossipd-all

default: gossipd-all

# Control daemon uses this:
LIGHTNINGD_GOSSIP_CONTROL_HEADERS := gossipd/gen_gossip_wire.h gossipd/gossip_constants.h
LIGHTNINGD_GOSSIP_CONTROL_SRC := gossipd/gen_gossip_wire.c
LIGHTNINGD_GOSSIP_CONTROL_OBJS := $(LIGHTNINGD_GOSSIP_CONTROL_SRC:.c=.o)

# gossipd needs these:
LIGHTNINGD_GOSSIP_HEADERS := gossipd/gen_gossip_wire.h \
	gossipd/gossip.h				\
	gossipd/gen_gossip_store.h			\
	gossipd/gossip_store.h				\
	gossipd/routing.h				\
	gossipd/broadcast.h
LIGHTNINGD_GOSSIP_SRC := $(LIGHTNINGD_GOSSIP_HEADERS:.h=.c)
LIGHTNINGD_GOSSIP_OBJS := $(LIGHTNINGD_GOSSIP_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_GOSSIP_OBJS)
ALL_PROGRAMS += lightningd/lightning_gossipd
ALL_GEN_HEADERS += gossipd/gen_gossip_wire.h

# For checking
LIGHTNINGD_GOSSIP_ALLSRC_NOGEN := $(filter-out gossipd/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_SRC) $(LIGHTNINGD_GOSSIP_SRC))
LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN := $(filter-out gossipd/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_GOSSIP_HEADERS)

# Common source we use.
GOSSIPD_COMMON_OBJS :=				\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bip32.o				\
	common/crypto_state.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/decode_short_channel_ids.o	\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/features.o			\
	common/gen_status_wire.o		\
	common/msg_queue.o			\
	common/ping.o				\
	common/pseudorand.o			\
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
	hsmd/client.o				\
	hsmd/gen_hsm_client_wire.o		\
	lightningd/gossip_msg.o			\
	wire/gen_onion_wire.o

$(LIGHTNINGD_GOSSIP_OBJS) $(LIGHTNINGD_GOSSIP_CLIENT_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS)

$(LIGHTNINGD_GOSSIP_CONTROL_OBJS) : $(LIGHTNINGD_GOSSIP_CONTROL_HEADERS)

gossipd-all: lightningd/lightning_gossipd $(LIGHTNINGD_GOSSIP_CLIENT_OBJS)

lightningd/lightning_gossipd: $(LIGHTNINGD_GOSSIP_OBJS) $(GOSSIPD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)

gossipd/gen_gossip_wire.h: $(WIRE_GEN) gossipd/gossip_wire.csv
	$(WIRE_GEN) --header $@ gossip_wire_type < gossipd/gossip_wire.csv > $@

gossipd/gen_gossip_wire.c: $(WIRE_GEN) gossipd/gossip_wire.csv
	$(WIRE_GEN) ${@:.c=.h} gossip_wire_type < gossipd/gossip_wire.csv > $@

gossipd/gen_gossip_store.h: $(WIRE_GEN) gossipd/gossip_store.csv
	$(WIRE_GEN) --header $@ gossip_store_type < gossipd/gossip_store.csv > $@

gossipd/gen_gossip_store.c: $(WIRE_GEN) gossipd/gossip_store.csv
	$(WIRE_GEN) ${@:.c=.h} gossip_store_type < gossipd/gossip_store.csv > $@


check-source: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_GOSSIP_SRC:%=bolt-check/%) $(LIGHTNINGD_GOSSIP_HEADERS:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: gossipd-clean

gossipd-clean:
	$(RM) $(LIGHTNINGD_GOSSIP_OBJS) gossipd/gen_*

-include gossipd/test/Makefile
