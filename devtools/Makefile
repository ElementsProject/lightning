DEVTOOLS := $(addprefix $(BUILDDIR)/devtools/,bolt11-cli decodemsg onion dump-gossipstore gossipwith create-gossipstore mkcommit mkfunding mkclose mkgossip mkencoded mkquery lightning-checkmessage topology route bolt12-cli encodeaddr features fp16 rune gossmap-compress bip137-verifysignature convert-gossmap)
ifeq ($(HAVE_SQLITE3),1)
DEVTOOLS += $(BUILDDIR)/devtools/checkchannels
endif

DEVTOOLS_TOOL_SRC := $(DEVTOOLS:$(BUILDDIR)/%=%.c) devtools/print_wire.c devtools/clean_topo.c
DEVTOOLS_TOOL_OBJS := $(DEVTOOLS_TOOL_SRC:%.c=$(BUILDDIR)/%.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(DEVTOOLS_TOOL_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(DEVTOOLS)

# gossmap-compress wants -lz if we say we have it.
ifeq ($(HAVE_ZLIB),1)
devtools/gossmap-compress_LDLIBS=-lz
endif # ZLIB

$(DEVTOOLS): %: %.o $(BUILDDIR)/libcommon.a
$(DEVTOOLS_TOOL_OBJS): wire/wire.h

# Some devtools require extra objects
$(BUILDDIR)/devtools/decodemsg: $(BUILDDIR)/devtools/print_wire.o
$(BUILDDIR)/devtools/decodemsg.o: devtools/print_wire.h

$(BUILDDIR)/devtools/mkcommit: $(addprefix $(BUILDDIR)/channeld/,full_channel.o commit_tx.o)
$(BUILDDIR)/devtools/mkcommit.o: channeld/full_channel.h channeld/commit_tx.h

$(BUILDDIR)/devtools/route $(BUILDDIR)/devtools/topology: $(BUILDDIR)/devtools/clean_topo.o
$(BUILDDIR)/devtools/route.o $(BUILDDIR)/devtools/topology.o: devtools/clean_topo.h
