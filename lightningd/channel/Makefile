#! /usr/bin/make

# Designed to be run one level up
lightningd/channel-wrongdir:
	$(MAKE) -C ../.. lightningd/channel-all

default: lightningd/channel-all

lightningd/channel-all: lightningd/lightningd_channel

# lightningd/channel needs these:
LIGHTNINGD_CHANNEL_HEADERS_GEN :=			\
	lightningd/channel/gen_channel_wire.h

LIGHTNINGD_CHANNEL_HEADERS_NOGEN :=

LIGHTNINGD_CHANNEL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS_GEN) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

LIGHTNINGD_CHANNEL_SRC := lightningd/channel/channel.c	\
	$(LIGHTNINGD_CHANNEL_HEADERS:.h=.c)
LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_CHANNEL_CONTROL_HEADERS := $(LIGHTNINGD_CHANNEL_HEADERS)
LIGHTNINGD_CHANNEL_CONTROL_SRC := $(LIGHTNINGD_CHANNEL_HEADERS:.h=.c)
LIGHTNINGD_CHANNEL_CONTROL_OBJS := $(LIGHTNINGD_CHANNEL_CONTROL_SRC:.c=.o)

LIGHTNINGD_CHANNEL_GEN_SRC := $(filter lightningd/channel/gen_%, $(LIGHTNINGD_CHANNEL_SRC) $(LIGHTNINGD_CHANNEL_CONTROL_SRC))

LIGHTNINGD_CHANNEL_SRC_NOGEN := $(filter-out lightningd/channel/gen_%, $(LIGHTNINGD_CHANNEL_SRC))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_CHANNEL_HEADERS_GEN)
LIGHTNINGD_HEADERS_NOGEN += $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN)

$(LIGHTNINGD_CHANNEL_OBJS): $(LIGHTNINGD_HEADERS)

lightningd/channel/gen_channel_wire.h: $(WIRE_GEN) lightningd/channel/channel_wire.csv
	$(WIRE_GEN) --header $@ channel_wire_type < lightningd/channel/channel_wire.csv > $@

lightningd/channel/gen_channel_wire.c: $(WIRE_GEN) lightningd/channel/channel_wire.csv
	$(WIRE_GEN) ${@:.c=.h} channel_wire_type < lightningd/channel/channel_wire.csv > $@

LIGHTNINGD_CHANNEL_OBJS := $(LIGHTNINGD_CHANNEL_SRC:.c=.o) $(LIGHTNINGD_CHANNEL_GEN_SRC:.c=.o)

lightningd/lightningd_channel: $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIGHTNINGD_CHANNEL_OBJS) $(WIRE_ONION_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(WIRE_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_HSM_CLIENT_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a libsodium.a libwallycore.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

check-source: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-src-include-order/%)
check-source-bolt: $(LIGHTNINGD_CHANNEL_SRC:%=bolt-check/%) $(LIGHTNINGD_CHANNEL_HEADERS:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_CHANNEL_SRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_CHANNEL_HEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/channel-clean

lightningd/channel-clean:
	$(RM) $(LIGHTNINGD_CHANNEL_OBJS) gen_*

-include lightningd/channel/test/Makefile 
