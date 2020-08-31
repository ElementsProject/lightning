#! /usr/bin/make

# Designed to be run one level up
hsmd-wrongdir:
	$(MAKE) -C .. lightningd/hsm-all

default: hsmd-all

LIGHTNINGD_HSM_SRC := hsmd/hsmd.c	\
	hsmd/hsmd_wiregen.c
LIGHTNINGD_HSM_HEADERS := hsmd/hsmd_wiregen.h
LIGHTNINGD_HSM_OBJS := $(LIGHTNINGD_HSM_SRC:.c=.o)

# Common source we use.
HSMD_COMMON_OBJS :=				\
	common/amount.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/channel_id.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/funding_tx.o			\
	common/status_wiregen.o			\
	common/hash_u5.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/permute_tx.o			\
	common/setup.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/withdraw_tx.o

LIGHTNINGD_HSM_CLIENT_OBJS := hsmd/hsmd_wiregen.o

# For checking
LIGHTNINGD_HSM_ALLSRC_NOGEN := $(filter-out hsmd/%wiregen.c, $(LIGHTNINGD_HSM_SRC) $(LIGHTNINGD_HSM_SRC))
LIGHTNINGD_HSM_ALLHEADERS_NOGEN := $(filter-out hsmd/%wiregen.h, $(LIGHTNINGD_HSM_HEADERS))

$(LIGHTNINGD_HSM_OBJS): $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_HSM_OBJS)
ALL_PROGRAMS += lightningd/lightning_hsmd
ALL_GEN_HEADERS += hsmd/hsmd_wiregen.h

hsmd-all: lightningd/lightning_hsmd

lightningd/lightning_hsmd: $(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_LIB_OBJS) $(HSMD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

check-source: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_HSM_SRC:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/hsm-clean

lightningd/hsm-clean:
	$(RM) $(LIGHTNINGD_HSM_OBJS)

-include hsmd/test/Makefile
