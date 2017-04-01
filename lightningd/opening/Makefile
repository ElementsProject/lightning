#! /usr/bin/make

# Designed to be run one level up
lightningd/opening-wrongdir:
	$(MAKE) -C ../.. lightningd/opening-all

default: lightningd/opening-all

lightningd/opening-all: lightningd/lightningd_opening

# lightningd/opening needs these:
LIGHTNINGD_OPENING_HEADERS_GEN :=			\
	lightningd/opening/gen_opening_wire.h

LIGHTNINGD_OPENING_HEADERS_NOGEN :=

LIGHTNINGD_OPENING_HEADERS := $(LIGHTNINGD_OPENING_HEADERS_GEN) $(LIGHTNINGD_OPENING_HEADERS_NOGEN)

LIGHTNINGD_OPENING_SRC := lightningd/opening/opening.c	\
	$(LIGHTNINGD_OPENING_HEADERS:.h=.c)
LIGHTNINGD_OPENING_OBJS := $(LIGHTNINGD_OPENING_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_OPENING_CONTROL_HEADERS := $(LIGHTNINGD_OPENING_HEADERS)
LIGHTNINGD_OPENING_CONTROL_SRC := $(LIGHTNINGD_OPENING_HEADERS:.h=.c)
LIGHTNINGD_OPENING_CONTROL_OBJS := $(LIGHTNINGD_OPENING_CONTROL_SRC:.c=.o)

LIGHTNINGD_OPENING_GEN_SRC := $(filter lightningd/opening/gen_%, $(LIGHTNINGD_OPENING_SRC) $(LIGHTNINGD_OPENING_CONTROL_SRC))

LIGHTNINGD_OPENING_SRC_NOGEN := $(filter-out lightningd/opening/gen_%, $(LIGHTNINGD_OPENING_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_OPENING_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_OPENING_HEADERS_NOGEN)

$(LIGHTNINGD_OPENING_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/opening/gen_opening_wire.h: $(WIRE_GEN) lightningd/opening/opening_wire.csv
	$(WIRE_GEN) --header $@ opening_wire_type < lightningd/opening/opening_wire.csv > $@

lightningd/opening/gen_opening_wire.c: $(WIRE_GEN) lightningd/opening/opening_wire.csv
	$(WIRE_GEN) ${@:.c=.h} opening_wire_type < lightningd/opening/opening_wire.csv > $@

LIGHTNINGD_OPENING_OBJS := $(LIGHTNINGD_OPENING_SRC:.c=.o) $(LIGHTNINGD_OPENING_GEN_SRC:.c=.o)

lightningd/lightningd_opening: $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_OPENING_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_HSM_CLIENT_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a libsodium.a libwallycore.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

check-source: $(LIGHTNINGD_OPENING_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_OPENING_SRC:%=bolt-check/%) $(LIGHTNINGD_OPENING_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_OPENING_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_OPENING_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/opening-clean

lightningd/opening-clean:
	$(RM) $(LIGHTNINGD_OPENING_OBJS) gen_*

-include lightningd/opening/test/Makefile 
