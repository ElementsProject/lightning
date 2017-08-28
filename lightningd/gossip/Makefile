#! /usr/bin/make

# Designed to be run one level up
lightningd/gossip-wrongdir:
	$(MAKE) -C .. lightningd/gossip-all

default: lightningd/gossip-all

# Control daemon uses this:
LIGHTNINGD_GOSSIP_CONTROL_HEADERS := lightningd/gossip/gen_gossip_wire.h
LIGHTNINGD_GOSSIP_CONTROL_SRC := lightningd/gossip/gen_gossip_wire.c
LIGHTNINGD_GOSSIP_CONTROL_OBJS := $(LIGHTNINGD_GOSSIP_CONTROL_SRC:.c=.o)

# lightningd/gossip needs these:
LIGHTNINGD_GOSSIP_HEADERS := lightningd/gossip/gen_gossip_wire.h \
	lightningd/gossip/routing.h				\
	lightningd/gossip/broadcast.h
LIGHTNINGD_GOSSIP_SRC := lightningd/gossip/gossip.c	\
	$(LIGHTNINGD_GOSSIP_HEADERS:.h=.c)
LIGHTNINGD_GOSSIP_OBJS := $(LIGHTNINGD_GOSSIP_SRC:.c=.o)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_GOSSIP_OBJS)

# For checking
LIGHTNINGD_GOSSIP_ALLSRC_NOGEN := $(filter-out lightningd/gossip/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_SRC) $(LIGHTNINGD_GOSSIP_SRC))
LIGHTNINGD_GOSSIP_ALLHEADERS_NOGEN := $(filter-out lightningd/gossip/gen_%, $(LIGHTNINGD_GOSSIP_CLIENT_HEADERS) $(LIGHTNINGD_GOSSIP_HEADERS))

# Add to headers which any object might need.
LIGHTNINGD_HEADERS_GEN += $(LIGHTNINGD_GOSSIP_HEADERS)

# Common source we use.
GOSSIPD_COMMON_OBJS :=				\
	common/crypto_sync.o			\
	common/cryptomsg.o			\
	common/daemon_conn.o			\
	common/debug.o				\
	common/dev_disconnect.o			\
	common/msg_queue.o			\
	common/ping.o				\
	common/pseudorand.o			\
	common/status.o				\
	common/timeout.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o			\
	lightningd/gossip_msg.o

$(LIGHTNINGD_GOSSIP_OBJS) $(LIGHTNINGD_GOSSIP_CLIENT_OBJS): $(LIGHTNINGD_HEADERS)

$(LIGHTNINGD_GOSSIP_CONTROL_OBJS) : $(LIGHTNINGD_GOSSIP_CONTROL_HEADERS)

lightningd/gossip-all: lightningd/lightningd_gossip $(LIGHTNINGD_GOSSIP_CLIENT_OBJS)

lightningd/lightningd_gossip: $(LIGHTNINGD_GOSSIP_OBJS) $(GOSSIPD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

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
