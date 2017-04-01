#! /usr/bin/make

# Designed to be run one level up
lightningd/hsm-wrongdir:
	$(MAKE) -C .. lightningd/hsm-all

default: lightningd/hsm-all

# Clients use this:
LIGHTNINGD_HSM_CLIENT_HEADERS := lightningd/hsm/client.h
LIGHTNINGD_HSM_CLIENT_SRC := lightningd/hsm/client.c lightningd/hsm/gen_hsm_client_wire.c
LIGHTNINGD_HSM_CLIENT_OBJS := $(LIGHTNINGD_HSM_CLIENT_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_HSM_CONTROL_HEADERS := lightningd/hsm/gen_hsm_wire.h
LIGHTNINGD_HSM_CONTROL_SRC := lightningd/hsm/gen_hsm_wire.c
LIGHTNINGD_HSM_CONTROL_OBJS := $(LIGHTNINGD_HSM_CONTROL_SRC:.c=.o)

# lightningd/hsm needs these:
LIGHTNINGD_HSM_HEADERS := lightningd/hsm/gen_hsm_client_wire.h	\
	lightningd/hsm/gen_hsm_wire.h
LIGHTNINGD_HSM_SRC := lightningd/hsm/hsm.c	\
	$(LIGHTNINGD_HSM_HEADERS:.h=.c)
LIGHTNINGD_HSM_OBJS := $(LIGHTNINGD_HSM_SRC:.c=.o)

# For checking
LIGHTNINGD_HSM_ALLSRC_NOGEN := $(filter-out lightningd/hsm/gen_%, $(LIGHTNINGD_HSM_CLIENT_SRC) $(LIGHTNINGD_HSM_SRC))
LIGHTNINGD_HSM_ALLHEADERS_NOGEN := $(filter-out lightningd/hsm/gen_%, $(LIGHTNINGD_HSM_CLIENT_HEADERS) $(LIGHTNINGD_HSM_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_HSM_HEADERS) $(LIGHTNINGD_HSM_CLIENT_HEADERS)

$(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS): $(LIGHTNINGD_HEADERS)

$(LIGHTNINGD_HSM_CONTROL_OBJS) : $(LIGHTNINGD_HSM_CONTROL_HEADERS)

$(LIGHTNINGD_HSM_OBJS): $(CORE_TX_HEADERS)

lightningd/hsm-all: lightningd/lightningd_hsm $(LIGHTNINGD_HSM_CLIENT_OBJS)

lightningd/lightningd_hsm: $(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIBBASE58_OBJS) lightningd/utxo.o libsecp256k1.a libsodium.a libwallycore.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

lightningd/hsm/gen_hsm_client_wire.h: $(WIRE_GEN) lightningd/hsm/hsm_client_wire_csv
	$(WIRE_GEN) --header $@ hsm_client_wire_type < lightningd/hsm/hsm_client_wire_csv > $@

lightningd/hsm/gen_hsm_client_wire.c: $(WIRE_GEN) lightningd/hsm/hsm_client_wire_csv
	$(WIRE_GEN) ${@:.c=.h} hsm_client_wire_type< lightningd/hsm/hsm_client_wire_csv > $@

lightningd/hsm/gen_hsm_wire.h: $(WIRE_GEN) lightningd/hsm/hsm_wire.csv
	$(WIRE_GEN) --header $@ hsm_wire_type < lightningd/hsm/hsm_wire.csv > $@

lightningd/hsm/gen_hsm_wire.c: $(WIRE_GEN) lightningd/hsm/hsm_wire.csv
	$(WIRE_GEN) ${@:.c=.h} hsm_wire_type < lightningd/hsm/hsm_wire.csv > $@

check-source: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_HSM_SRC:%=bolt-check/%) $(LIGHTNINGD_HSM_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/hsm-clean

lightningd/hsm-clean:
	$(RM) $(LIGHTNINGD_HSM_OBJS) gen_*

-include lightningd/hsm/test/Makefile 
