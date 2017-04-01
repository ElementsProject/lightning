#! /usr/bin/make

# Designed to be run one level up
lightningd/gossip-wrongdir:
	$(MAKE) -C .. lightningd/gossip-all

default: lightningd/gossip-all

# Control daemon uses this:
LIGHTNINGD_GOSSIP_CONTROL_HEADERS := lightningd/gossip/gen_gossip_wire.h
LIGHTNINGD_GOSSIP_CONTROL_SRC := lightningd/gossip/gen_gossip_wire.c
LIGHTNINGD_GOSSIP_CONTROL_OBJS := $(LIGHTNINGD_GOSSIP_CONTROL_SRC:.c=.o)

# These should eventually be migrated to the lightningd directory, after
# deprecating the legacy daemons
LIGHTNINGD_GOSSIP_LEGACY_HEADERS := daemon/routing.h daemon/broadcast.h \
	daemon/log.h

# lightningd/gossip needs these:
LIGHTNINGD_GOSSIP_HEADERS := lightningd/gossip/gen_gossip_wire.h \
	$(LIGHTNINGD_GOSSIP_LEGACY_HEADERS)
LIGHTNINGD_GOSSIP_SRC := lightningd/gossip/gossip.c	\
	$(LIGHTNINGD_GOSSIP_HEADERS:.h=.c)
LIGHTNINGD_GOSSIP_OBJS := $(LIGHTNINGD_GOSSIP_SRC:.c=.o)

# For checking
LIGHTNINGD_GOSSIP_ALLSRC_NOGEN := $(filter-out lightningd/gossip/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_SRC) $(LIGHTNINGD_GOSSIP_SRC))
LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN := $(filter-out lightningd/gossip/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_GOSSIP_HEADERS)

$(LIGHTNINGD_GOSSIP_OBJS) $(LIGHTNINGD_GOSSIP_CLIENT_OBJS): $(LIGHTNINGD_HEADERS)

$(LIGHTNINGD_GOSSIP_CONTROL_OBJS) : $(LIGHTNINGD_GOSSIP_CONTROL_HEADERS)

lightningd/gossip-all: lightningd/lightningd_gossip $(LIGHTNINGD_GOSSIP_CLIENT_OBJS)

lightningd/lightningd_gossip: $(LIGHTNINGD_GOSSIP_OBJS) $(CORE_OBJS) $(CORE_TX_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(LIGHTNINGD_OLD_LIB_OBJS) $(LIGHTNINGD_LIB_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a libsodium.a libwallycore.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

lightningd/gossip/gen_gossip_wire.h: $(WIRE_GEN) lightningd/gossip/gossip_wire.csv
	$(WIRE_GEN) --header $@ gossip_wire_type < lightningd/gossip/gossip_wire.csv > $@

lightningd/gossip/gen_gossip_wire.c: $(WIRE_GEN) lightningd/gossip/gossip_wire.csv
	$(WIRE_GEN) ${@:.c=.h} gossip_wire_type < lightningd/gossip/gossip_wire.csv > $@

check-source: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_GOSSIP_SRC:%=bolt-check/%) $(LIGHTNINGD_GOSSIP_HEADERS:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_GOSSIP_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/gossip-clean

lightningd/gossip-clean:
	$(RM) $(LIGHTNINGD_GOSSIP_OBJS) gen_*

-include lightningd/gossip/test/Makefile 
