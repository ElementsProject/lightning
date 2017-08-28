#! /usr/bin/make

# Designed to be run one level up
lightningd/closing-wrongdir:
	$(MAKE) -C ../.. lightningd/closing-all

default: lightningd/closing-all

lightningd/closing-all: lightningd/lightningd_closing

# lightningd/closing needs these:
LIGHTNINGD_CLOSING_HEADERS_GEN :=			\
	lightningd/closing/gen_closing_wire.h

LIGHTNINGD_CLOSING_HEADERS_NOGEN :=

LIGHTNINGD_CLOSING_HEADERS := $(LIGHTNINGD_CLOSING_HEADERS_GEN) $(LIGHTNINGD_CLOSING_HEADERS_NOGEN)

LIGHTNINGD_CLOSING_SRC := lightningd/closing/closing.c	\
	$(LIGHTNINGD_CLOSING_HEADERS:.h=.c)
LIGHTNINGD_CLOSING_OBJS := $(LIGHTNINGD_CLOSING_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_CLOSING_CONTROL_HEADERS := $(LIGHTNINGD_CLOSING_HEADERS)
LIGHTNINGD_CLOSING_CONTROL_SRC := $(LIGHTNINGD_CLOSING_HEADERS:.h=.c)
LIGHTNINGD_CLOSING_CONTROL_OBJS := $(LIGHTNINGD_CLOSING_CONTROL_SRC:.c=.o)

LIGHTNINGD_CLOSING_GEN_SRC := $(filter lightningd/closing/gen_%, $(LIGHTNINGD_CLOSING_SRC) $(LIGHTNINGD_CLOSING_CONTROL_SRC))

LIGHTNINGD_CLOSING_SRC_NOGEN := $(filter-out lightningd/closing/gen_%, $(LIGHTNINGD_CLOSING_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_CLOSING_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_CLOSING_HEADERS_NOGEN)

$(LIGHTNINGD_CLOSING_OBJS): $(LIGHTNINGD_HEADERS)

# Common source we use.
CLOSINGD_COMMON_OBJS :=				\
	common/close_tx.o			\
	common/derive_basepoints.o		\
	common/permute_tx.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o

lightningd/closing/gen_closing_wire.h: $(WIRE_GEN) lightningd/closing/closing_wire.csv
	$(WIRE_GEN) --header $@ closing_wire_type < lightningd/closing/closing_wire.csv > $@

lightningd/closing/gen_closing_wire.c: $(WIRE_GEN) lightningd/closing/closing_wire.csv
	$(WIRE_GEN) ${@:.c=.h} closing_wire_type < lightningd/closing/closing_wire.csv > $@

LIGHTNINGD_CLOSING_OBJS := $(LIGHTNINGD_CLOSING_SRC:.c=.o) $(LIGHTNINGD_CLOSING_GEN_SRC:.c=.o)

lightningd/lightningd_closing: $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_CLOSING_OBJS) $(WIRE_ONION_OBJS) $(CLOSINGD_COMMON_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_HSM_CLIENT_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a libsodium.a libwallycore.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

check-source: $(LIGHTNINGD_CLOSING_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_CLOSING_SRC:%=bolt-check/%) $(LIGHTNINGD_CLOSING_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_CLOSING_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_CLOSING_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/closing-clean

lightningd/closing-clean:
	$(RM) $(LIGHTNINGD_CLOSING_OBJS) gen_*

-include lightningd/closing/test/Makefile 
