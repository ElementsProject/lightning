#! /usr/bin/make

CLOSINGD_HEADERS := closingd/closingd_wiregen.h

CLOSINGD_SRC := closingd/closingd.c	\
	$(CLOSINGD_HEADERS:.h=.c)

CLOSINGD_OBJS := $(CLOSINGD_SRC:.c=.o)
$(CLOSINGD_OBJS): $(CLOSINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CLOSINGD_SRC)
ALL_C_HEADERS += $(CLOSINGD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_closingd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += closingd/closingd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += closingd/closingd_wiregen.o

# Common source we use.
CLOSINGD_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/channel_id.o			\
	common/close_tx.o			\
	common/cryptomsg.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/gossip_store.o			\
	common/htlc_wire.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/peer_billboard.o			\
	common/peer_failed.o			\
	common/peer_io.o			\
	common/peer_status_wiregen.o		\
	common/per_peer_state.o			\
	common/permute_tx.o			\
	common/ping.o				\
	common/psbt_keypath.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/status_wiregen.o			\
	common/read_peer_msg.o			\
	common/setup.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	gossipd/gossip_store_wiregen.o		\
	gossipd/gossipd_peerd_wiregen.o

lightningd/lightning_closingd: $(CLOSINGD_OBJS) $(CLOSINGD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(HSMD_CLIENT_OBJS)

-include closingd/test/Makefile
