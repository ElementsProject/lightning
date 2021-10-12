#! /usr/bin/make

ONCHAIND_HEADERS :=				\
	onchaind/onchaind_wiregen.h		\
	onchaind/onchain_types_names_gen.h	\
	onchaind/onchain_types.h		\
	onchaind/onchaind_wire.h

ONCHAIND_SRC := onchaind/onchaind.c	\
	onchaind/onchaind_wiregen.c	\
	onchaind/onchaind_wire.c	\
	onchaind/onchaind.c

onchaind/onchain_types_names_gen.h: onchaind/onchain_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr onchaind/onchain_types.h > $@

ONCHAIND_OBJS := $(ONCHAIND_SRC:.c=.o)
$(ONCHAIND_OBJS): $(ONCHAIND_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(ONCHAIND_SRC)
ALL_C_HEADERS += $(ONCHAIND_HEADERS)
ALL_PROGRAMS += lightningd/lightning_onchaind

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += \
	onchaind/onchaind_wiregen.h \
	onchaind/onchaind_wire.h
LIGHTNINGD_CONTROL_OBJS += \
	onchaind/onchaind_wiregen.o \
	onchaind/onchaind_wire.o

# Common source we use.
ONCHAIND_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/coin_mvt.o			\
	common/channel_id.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/status_wiregen.o			\
	common/htlc_tx.o			\
	common/htlc_wire.o			\
	common/initial_commit_tx.o		\
	common/keyset.o				\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onionreply.o			\
	common/peer_billboard.o			\
	common/permute_tx.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/wallet.o				\
	common/wireaddr.o

lightningd/lightning_onchaind: $(ONCHAIND_OBJS) $(WIRE_ONION_OBJS) $(ONCHAIND_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(HSMD_CLIENT_OBJS)

include onchaind/test/Makefile
