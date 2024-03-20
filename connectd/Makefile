#! /usr/bin/make

CONNECTD_HEADERS := connectd/connectd_wiregen.h		\
	connectd/connectd_gossipd_wiregen.h		\
	connectd/connectd.h				\
	connectd/peer_exchange_initmsg.h		\
	connectd/handshake.h				\
	connectd/gossip_store.h				\
	connectd/gossip_rcvd_filter.h			\
	connectd/multiplex.h				\
	connectd/netaddress.h				\
	connectd/onion_message.h			\
	connectd/tor_autoservice.h			\
	connectd/tor.h

CONNECTD_SRC := $(CONNECTD_HEADERS:.h=.c) connectd/connectd.c

CONNECTD_OBJS := $(CONNECTD_SRC:.c=.o)
$(CONNECTD_OBJS): $(CONNECTD_HEADERS)

WEBSOCKETD_HEADERS := connectd/sha1.h
WEBSOCKETD_SRC := $(WEBSOCKETD_HEADERS:.h=.c) connectd/websocketd.c

WEBSOCKETD_OBJS := $(WEBSOCKETD_SRC:.c=.o)
$(WEBSOCKETD_OBJS): $(WEBSOCKETD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CONNECTD_SRC) $(WEBSOCKETD_SRC)
ALL_C_HEADERS += $(CONNECTD_HEADERS) $(WEBSOCKETD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_connectd
ALL_PROGRAMS += lightningd/lightning_websocketd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += connectd/connectd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += connectd/connectd_wiregen.o

# Common source we use.
CONNECTD_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/base64.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bip32.o				\
	common/blinding.o			\
	common/blindedpath.o			\
	common/channel_id.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/ecdh_hsmd.o			\
	common/features.o			\
	common/hmac.o				\
	common/status_wiregen.o			\
	common/gossip_store.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onion_decode.o			\
	common/onionreply.o			\
	common/onion_message_parse.o		\
	common/ping.o				\
	common/per_peer_state.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/sphinx.o				\
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
	gossipd/gossipd_wiregen.o		\
	gossipd/gossip_store_wiregen.o		\
	wire/onion_wiregen.o

lightningd/lightning_connectd: $(CONNECTD_OBJS) $(CONNECTD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(HSMD_CLIENT_OBJS)

lightningd/lightning_websocketd: $(WEBSOCKETD_OBJS) common/setup.o common/utils.o common/autodata.o

include connectd/test/Makefile
