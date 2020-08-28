#! /usr/bin/make

OPENINGD_HEADERS := openingd/openingd_wiregen.h

OPENINGD_SRC := openingd/openingd.c	\
	$(OPENINGD_HEADERS:.h=.c)

OPENINGD_OBJS := $(OPENINGD_SRC:.c=.o)
$(OPENINGD_OBJS): $(OPENINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(OPENINGD_SRC)
ALL_C_HEADERS += $(OPENINGD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_openingd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += openingd/openingd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += openingd/openingd_wiregen.o

# Common source we use.
OPENINGD_COMMON_OBJS :=				\
	common/amount.o				\
	common/base32.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/channel_config.o			\
	common/channel_id.o			\
	common/crypto_state.o			\
	common/crypto_sync.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/dev_disconnect.o			\
	common/features.o			\
	common/fee_states.o			\
	common/status_wiregen.o			\
	common/peer_status_wiregen.o		\
	common/gossip_rcvd_filter.o		\
	common/gossip_store.o			\
	common/htlc_state.o			\
	common/htlc_wire.o			\
	common/initial_channel.o		\
	common/initial_commit_tx.o		\
	common/key_derive.o			\
	common/keyset.o				\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/penalty_base.o			\
	common/per_peer_state.o			\
	common/peer_billboard.o			\
	common/peer_failed.o			\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/read_peer_msg.o			\
	common/setup.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	gossipd/gossipd_peerd_wiregen.o		\
	lightningd/gossip_msg.o

lightningd/lightning_openingd: $(OPENINGD_OBJS) $(OPENINGD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(HSMD_CLIENT_OBJS)

-include openingd/test/Makefile
