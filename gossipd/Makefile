#! /usr/bin/make

GOSSIPD_HEADERS_WSRC := gossipd/gossipd_wiregen.h \
	gossipd/gossipd.h				\
	gossipd/gossip_store.h				\
	gossipd/gossmap_manage.h			\
	gossipd/queries.h				\
	gossipd/txout_failures.h			\
	gossipd/sigcheck.h				\
	gossipd/seeker.h
GOSSIPD_HEADERS := $(GOSSIPD_HEADERS_WSRC)

GOSSIPD_SRC := $(GOSSIPD_HEADERS_WSRC:.h=.c)
GOSSIPD_OBJS := $(GOSSIPD_SRC:.c=.o)
$(GOSSIPD_OBJS): $(GOSSIPD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(GOSSIPD_SRC)
ALL_C_HEADERS += $(GOSSIPD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_gossipd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += gossipd/gossipd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += gossipd/gossipd_wiregen.o

lightningd/lightning_gossipd: $(GOSSIPD_OBJS) $(HSMD_CLIENT_OBJS) connectd/connectd_gossipd_wiregen.o libcommon.a

# The CSV was removed, but the generated files may live on!
clean: clean-old-gossip-gen

clean-old-gossip-gen:
	$(RM) gossipd_peerd_wiregen.*

include gossipd/test/Makefile
