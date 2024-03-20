#! /usr/bin/make

OPENINGD_HEADERS := 				\
	openingd/common.h			\
	openingd/openingd_wiregen.h

DUALOPEND_HEADERS := 				\
	openingd/common.h			\
	openingd/dualopend_wiregen.h

OPENINGD_SRC := openingd/openingd.c		\
	$(OPENINGD_HEADERS:.h=.c)

DUALOPEND_SRC := openingd/dualopend.c		\
	$(DUALOPEND_HEADERS:.h=.c)

OPENINGD_OBJS := $(OPENINGD_SRC:.c=.o)
$(OPENINGD_OBJS): $(OPENINGD_HEADERS)

DUALOPEND_OBJS := $(DUALOPEND_SRC:.c=.o)
$(DUALOPEND_OBJS): $(DUALOPEND_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(OPENINGD_SRC) $(DUALOPEND_SRC)
ALL_C_HEADERS += $(OPENINGD_HEADERS) $(DUALOPEND_HEADERS)
ALL_PROGRAMS += lightningd/lightning_openingd lightningd/lightning_dualopend

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += openingd/openingd_wiregen.h openingd/dualopend_wiregen.h
LIGHTNINGD_CONTROL_OBJS += openingd/openingd_wiregen.o openingd/dualopend_wiregen.o

# Common source we use.
OPENINGD_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bigsize.o			\
	common/billboard.o			\
	common/bip32.o				\
	common/blockheight_states.o		\
	common/channel_config.o			\
	common/channel_id.o			\
	common/channel_type.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/features.o			\
	common/fee_states.o			\
	common/gossip_store.o			\
	common/htlc_state.o			\
	common/htlc_wire.o			\
	common/initial_channel.o		\
	common/initial_commit_tx.o		\
	common/key_derive.o			\
	common/keyset.o				\
	common/lease_rates.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/peer_billboard.o			\
	common/peer_failed.o			\
	common/peer_io.o			\
	common/peer_status_wiregen.o		\
	common/penalty_base.o			\
	common/per_peer_state.o			\
	common/permute_tx.o			\
	common/ping.o				\
	common/psbt_internal.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/read_peer_msg.o			\
	common/setup.o				\
	common/shutdown_scriptpubkey.o		\
	common/status.o				\
	common/status_wire.o			\
	common/status_wiregen.o			\
	common/subdaemon.o			\
	common/tx_roles.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	gossipd/gossip_store_wiregen.o		\
	gossipd/gossipd_peerd_wiregen.o

lightningd/lightning_openingd: $(OPENINGD_OBJS) $(OPENINGD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(HSMD_CLIENT_OBJS)

lightningd/lightning_dualopend: $(DUALOPEND_OBJS) $(OPENINGD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(HSMD_CLIENT_OBJS)

-include openingd/test/Makefile
