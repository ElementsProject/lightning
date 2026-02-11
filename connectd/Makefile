#! /usr/bin/make

CONNECTD_HEADERS := connectd/connectd_wiregen.h		\
	connectd/connectd_gossipd_wiregen.h		\
	connectd/connectd.h				\
	connectd/peer_exchange_initmsg.h		\
	connectd/handshake.h				\
	connectd/gossip_store.h				\
	connectd/gossip_rcvd_filter.h			\
	connectd/queries.h				\
	connectd/multiplex.h				\
	connectd/netaddress.h				\
	connectd/onion_message.h			\
	connectd/tor_autoservice.h			\
	connectd/tor.h

CONNECTD_SRC := $(CONNECTD_HEADERS:.h=.c) connectd/connectd.c

CONNECTD_OBJS := $(CONNECTD_SRC:.c=.o)
$(CONNECTD_OBJS): $(CONNECTD_HEADERS)

WEBSOCKETD_HEADERS := connectd/sha1.h
WEBSOCKETD_SRC := $(WEBSOCKETD_HEADERS:.h=.c) connectd/websocketd.c

WEBSOCKETD_OBJS := $(WEBSOCKETD_SRC:.c=.o)
$(WEBSOCKETD_OBJS): $(WEBSOCKETD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CONNECTD_SRC) $(WEBSOCKETD_SRC)
ALL_C_HEADERS += $(CONNECTD_HEADERS) $(WEBSOCKETD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_connectd
ALL_PROGRAMS += lightningd/lightning_websocketd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += connectd/connectd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += connectd/connectd_wiregen.o

lightningd/lightning_connectd: $(CONNECTD_OBJS) $(HSMD_CLIENT_OBJS) gossipd/gossipd_wiregen.o libcommon.a

lightningd/lightning_websocketd: $(WEBSOCKETD_OBJS) libcommon.a

include connectd/test/Makefile
