#! /usr/bin/make

# Designed to be run one level up
hsmd-wrongdir:
	$(MAKE) -C .. lightningd/hsm-all

default: hsmd-all

# Clients use this:
LIGHTNINGD_HSM_CLIENT_HEADERS := hsmd/client.h
LIGHTNINGD_HSM_CLIENT_SRC := hsmd/client.c hsmd/gen_hsm_client_wire.c
LIGHTNINGD_HSM_CLIENT_OBJS := $(LIGHTNINGD_HSM_CLIENT_SRC:.c=.o)

# lightningd/hsm needs these:
LIGHTNINGD_HSM_HEADERS := hsmd/gen_hsm_client_wire.h

LIGHTNINGD_HSM_SRC := hsmd/hsm.c	\
	$(LIGHTNINGD_HSM_HEADERS:.h=.c)
LIGHTNINGD_HSM_OBJS := $(LIGHTNINGD_HSM_SRC:.c=.o)

# Common source we use.
HSMD_COMMON_OBJS :=				\
	common/bip32.o				\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/funding_tx.o			\
	common/gen_status_wire.o		\
	common/hash_u5.o			\
	common/key_derive.o			\
	common/msg_queue.o			\
	common/permute_tx.o			\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/withdraw_tx.o

# For checking
LIGHTNINGD_HSM_ALLSRC_NOGEN := $(filter-out hsmd/gen_%, $(LIGHTNINGD_HSM_CLIENT_SRC) $(LIGHTNINGD_HSM_SRC))
LIGHTNINGD_HSM_ALLHEADERS_NOGEN := $(filter-out hsmd/gen_%, $(LIGHTNINGD_HSM_CLIENT_HEADERS) $(LIGHTNINGD_HSM_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_HSM_HEADERS) $(LIGHTNINGD_HSM_CLIENT_HEADERS)

$(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS): $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS)
ALL_PROGRAMS += lightningd/lightning_hsmd
ALL_GEN_HEADERS += $(LIGHTNINGD_HSM_HEADERS)

hsmd-all: lightningd/lightning_hsmd $(LIGHTNINGD_HSM_CLIENT_OBJS)

lightningd/lightning_hsmd: $(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_LIB_OBJS) $(HSMD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

hsmd/gen_hsm_client_wire.h: $(WIRE_GEN) hsmd/hsm_client_wire_csv
	$(WIRE_GEN) --header $@ hsm_client_wire_type < hsmd/hsm_client_wire_csv > $@

hsmd/gen_hsm_client_wire.c: $(WIRE_GEN) hsmd/hsm_client_wire_csv
	$(WIRE_GEN) ${@:.c=.h} hsm_client_wire_type< hsmd/hsm_client_wire_csv > $@

hsmd/gen_hsm_wire.h: $(WIRE_GEN) hsmd/hsm_wire.csv
	$(WIRE_GEN) --header $@ hsm_wire_type < hsmd/hsm_wire.csv > $@

hsmd/gen_hsm_wire.c: $(WIRE_GEN) hsmd/hsm_wire.csv
	$(WIRE_GEN) ${@:.c=.h} hsm_wire_type < hsmd/hsm_wire.csv > $@

check-source: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_HSM_SRC:%=bolt-check/%) $(LIGHTNINGD_HSM_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/hsm-clean

lightningd/hsm-clean:
	$(RM) $(LIGHTNINGD_HSM_OBJS) hsmd/gen_*

-include hsmd/test/Makefile
