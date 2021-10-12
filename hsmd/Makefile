#! /usr/bin/make

HSMD_SRC := hsmd/hsmd.c	\
	hsmd/hsmd_wiregen.c \
	hsmd/libhsmd.c

HSMD_HEADERS := hsmd/hsmd_wiregen.h
HSMD_OBJS := $(HSMD_SRC:.c=.o)

$(HSMD_OBJS): $(HSMD_HEADERS)

# Other programs which use the hsm need this.
HSMD_CLIENT_OBJS := hsmd/hsmd_wiregen.o

# Make sure these depend on everything.
ALL_C_SOURCES += $(HSMD_SRC)
ALL_C_HEADERS += $(HSMD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_hsmd

# Common source we use.
HSMD_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/bolt12_merkle.o			\
	common/channel_id.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/status_wiregen.o			\
	common/hash_u5.o			\
	common/hsm_encryption.o			\
	common/key_derive.o			\
	common/lease_rates.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
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
	common/wireaddr.o

lightningd/lightning_hsmd: $(HSMD_OBJS) $(HSMD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

-include hsmd/test/Makefile
