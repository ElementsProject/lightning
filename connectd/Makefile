#! /usr/bin/make

# Designed to be run one level up
connectd-wrongdir:
	$(MAKE) -C .. connectd-all

default: connectd-all

# Control daemon uses this:
LIGHTNINGD_CONNECT_CONTROL_HEADERS := connectd/gen_connect_wire.h connectd/gen_connect_gossip_wire.h
LIGHTNINGD_CONNECT_CONTROL_SRC := connectd/gen_connect_wire.c connectd/gen_connect_gossip_wire.c
LIGHTNINGD_CONNECT_CONTROL_OBJS := $(LIGHTNINGD_CONNECT_CONTROL_SRC:.c=.o)

# connectd needs these:
LIGHTNINGD_CONNECT_HEADERS := connectd/gen_connect_wire.h \
	connectd/gen_connect_gossip_wire.h		\
	connectd/connect.h				\
	connectd/handshake.h				\
	connectd/netaddress.h				\
	connectd/tor_autoservice.h			\
	connectd/tor.h
LIGHTNINGD_CONNECT_SRC := $(LIGHTNINGD_CONNECT_HEADERS:.h=.c)
LIGHTNINGD_CONNECT_OBJS := $(LIGHTNINGD_CONNECT_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_CONNECT_OBJS)
ALL_PROGRAMS += lightningd/lightning_connectd
ALL_GEN_HEADERS += connectd/gen_connect_wire.h connectd/gen_connect_gossip_wire.h

# For checking
LIGHTNINGD_CONNECT_ALLSRC_NOGEN := $(filter-out connectd/gen_%, $(LIGHTNINGD_CONNECT_CLIENT_SRC) $(LIGHTNINGD_CONNECT_SRC))
LIGHTNINGD_CONNECT_ALLHEADERS_NOGEN := $(filter-out connectd/gen_%, $(LIGHTNINGD_CONNECT_CLIENT_HEADERS) $(LIGHTNINGD_CONNECT_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_CONNECT_HEADERS)

# Common source we use.
CONNECTD_COMMON_OBJS :=				\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bip32.o				\
	common/crypto_state.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/features.o			\
	common/gen_status_wire.o		\
	common/msg_queue.o			\
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
	gossipd/gen_gossip_wire.o		\
	hsmd/client.o				\
	hsmd/gen_hsm_client_wire.o		\
	lightningd/gossip_msg.o			\
	wire/gen_onion_wire.o

$(LIGHTNINGD_CONNECT_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_CONNECT_HEADERS)

$(LIGHTNINGD_CONNECT_CONTROL_OBJS) : $(LIGHTNINGD_CONNECT_CONTROL_HEADERS)

connectd-all: lightningd/lightning_connectd

lightningd/lightning_connectd: $(LIGHTNINGD_CONNECT_OBJS) $(CONNECTD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

connectd/gen_connect_wire.h: $(WIRE_GEN) connectd/connect_wire.csv
	$(WIRE_GEN) --header $@ connect_wire_type < connectd/connect_wire.csv > $@

connectd/gen_connect_wire.c: $(WIRE_GEN) connectd/connect_wire.csv
	$(WIRE_GEN) ${@:.c=.h} connect_wire_type < connectd/connect_wire.csv > $@

connectd/gen_connect_gossip_wire.h: $(WIRE_GEN) connectd/connect_gossip_wire.csv
	$(WIRE_GEN) --header $@ connect_gossip_wire_type < connectd/connect_gossip_wire.csv > $@

connectd/gen_connect_gossip_wire.c: $(WIRE_GEN) connectd/connect_gossip_wire.csv
	$(WIRE_GEN) ${@:.c=.h} connect_gossip_wire_type < connectd/connect_gossip_wire.csv > $@

check-source: $(LIGHTNINGD_CONNECT_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_CONNECT_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_CONNECT_SRC:%=bolt-check/%) $(LIGHTNINGD_CONNECT_HEADERS:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_CONNECT_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_CONNECT_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: connectd-clean

connectd-clean:
	$(RM) $(LIGHTNINGD_CONNECT_OBJS) connectd/gen_*

-include connectd/test/Makefile
