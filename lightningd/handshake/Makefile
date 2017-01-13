#! /usr/bin/make

# Designed to be run one level up
lightningd/handshake-wrongdir:
	$(MAKE) -C .. lightningd/handshake-all

default: lightningd/handshake-all

lightningd/handshake-all: lightningd/lightningd_handshake

# lightningd/handshake needs these:
LIGHTNINGD_HANDSHAKE_HEADERS :=					\
	lightningd/handshake/gen_handshake_control_wire.h	\
	lightningd/handshake/gen_handshake_status_wire.h
LIGHTNINGD_HANDSHAKE_SRC := lightningd/handshake/handshake.c	\
	$(LIGHTNINGD_HANDSHAKE_HEADERS:.h=.c)
LIGHTNINGD_HANDSHAKE_OBJS := $(LIGHTNINGD_HANDSHAKE_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_HANDSHAKE_CONTROL_HEADERS := $(LIGHTNINGD_HANDSHAKE_HEADERS)
LIGHTNINGD_HANDSHAKE_CONTROL_SRC := $(LIGHTNINGD_HANDSHAKE_HEADERS:.h=.c)
LIGHTNINGD_HANDSHAKE_CONTROL_OBJS := $(LIGHTNINGD_HANDSHAKE_CONTROL_SRC:.c=.o)

LIGHTNINGD_HANDSHAKE_GEN_SRC := $(filter lightningd/handshake/gen_%, $(LIGHTNINGD_HANDSHAKE_SRC) $(LIGHTNINGD_HANDSHAKE_CONTROL_SRC))

LIGHTNINGD_HANDSHAKE_SRC_NOGEN := $(filter-out lightningd/handshake/gen_%, $(LIGHTNINGD_HANDSHAKE_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_HANDSHAKE_HEADERS)

$(LIGHTNINGD_HANDSHAKE_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/handshake/gen_handshake_control_wire.h: $(WIRE_GEN) lightningd/handshake/handshake_control_wire_csv
	$(WIRE_GEN) --header $@ handshake_control_wire_type < lightningd/handshake/handshake_control_wire_csv > $@

lightningd/handshake/gen_handshake_control_wire.c: $(WIRE_GEN) lightningd/handshake/handshake_control_wire_csv
	$(WIRE_GEN) ${@:.c=.h} handshake_control_wire_type < lightningd/handshake/handshake_control_wire_csv > $@

lightningd/handshake/gen_handshake_status_wire.h: $(WIRE_GEN) lightningd/handshake/handshake_status_wire_csv
	$(WIRE_GEN) --header $@ handshake_status_wire_type < lightningd/handshake/handshake_status_wire_csv > $@

lightningd/handshake/gen_handshake_status_wire.c: $(WIRE_GEN) lightningd/handshake/handshake_status_wire_csv
	$(WIRE_GEN) ${@:.c=.h} handshake_status_wire_type < lightningd/handshake/handshake_status_wire_csv > $@

LIGHTNINGD_HANDSHAKE_OBJS := $(LIGHTNINGD_HANDSHAKE_SRC:.c=.o) $(LIGHTNINGD_HANDSHAKE_GEN_SRC:.c=.o)

lightningd/lightningd_handshake: $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_HANDSHAKE_OBJS) $(CORE_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a libsodium.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

check-source: $(LIGHTNINGD_HANDSHAKE_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_HANDSHAKE_SRC:%=bolt-check/%) $(LIGHTNINGD_HANDSHAKE_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_HANDSHAKE_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_HANDSHAKE_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/handshake-clean

lightningd/handshake-clean:
	$(RM) $(LIGHTNINGD_HANDSHAKE_OBJS) gen_*

-include lightningd/handshake/test/Makefile 
