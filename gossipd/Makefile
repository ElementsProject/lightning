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
GOSSIPD_OBJS := $(GOSSIPD_SRC:%.c=$(BUILDDIR)/%.o)
$(GOSSIPD_OBJS): $(GOSSIPD_HEADERS)

GOSSIPD_COMPACT_SRC := gossipd/compactd.c
GOSSIPD_COMPACT_OBJS := $(GOSSIPD_COMPACT_SRC:%.c=$(BUILDDIR)/%.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(GOSSIPD_SRC) $(GOSSIPD_COMPACT_SRC)
ALL_C_HEADERS += $(GOSSIPD_HEADERS)
ALL_PROGRAMS += $(addprefix $(BUILDDIR)/lightningd/,lightning_gossipd lightning_gossip_compactd)

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += gossipd/gossipd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += $(BUILDDIR)/gossipd/gossipd_wiregen.o

$(BUILDDIR)/lightningd/lightning_gossipd: $(GOSSIPD_OBJS) $(HSMD_CLIENT_OBJS) $(addprefix $(BUILDDIR)/,connectd/connectd_gossipd_wiregen.o libcommon.a)

$(BUILDDIR)/lightningd/lightning_gossip_compactd: $(GOSSIPD_COMPACT_OBJS) $(BUILDDIR)/libcommon.a

obsclean::
	$(RM) gossipd_peerd_wiregen.* gossipd/*.o

include gossipd/test/Makefile
