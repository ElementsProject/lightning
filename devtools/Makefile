DEVTOOLS := devtools/bolt11-cli devtools/decodemsg devtools/onion devtools/dump-gossipstore devtools/gossipwith devtools/create-gossipstore devtools/mkcommit devtools/mkfunding devtools/mkclose devtools/mkgossip devtools/mkencoded devtools/mkquery devtools/lightning-checkmessage devtools/topology devtools/route devtools/bolt12-cli devtools/encodeaddr devtools/features devtools/fp16 devtools/rune devtools/gossmap-compress devtools/bip137-verifysignature devtools/convert-gossmap devtools/check-bolt
ifeq ($(HAVE_SQLITE3),1)
DEVTOOLS += devtools/checkchannels
endif

DEVTOOLS_TOOL_SRC := $(DEVTOOLS:=.c) devtools/print_wire.c devtools/clean_topo.c
DEVTOOLS_TOOL_OBJS := $(DEVTOOLS_TOOL_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(DEVTOOLS_TOOL_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(DEVTOOLS)

# gossmap-compress wants -lz if we say we have it.
ifeq ($(HAVE_ZLIB),1)
devtools/gossmap-compress_LDLIBS=-lz
endif # ZLIB

$(DEVTOOLS): %: %.o libcommon.a
$(DEVTOOLS_TOOL_OBJS): wire/wire.h

# Some devtools require extra objects
DEVTOOLS_NEEDS_GOSSIP_STORE := devtools/gossmap-compress devtools/dump-gossipstore devtools/convert-gossmap devtools/create-gossipstore

$(DEVTOOLS_NEEDS_GOSSIP_STORE): gossipd/gossip_store_wiregen.o
$(DEVTOOLS_NEEDS_GOSSIP_STORE:=.o): gossipd/gossip_store_wiregen.h

devtools/decodemsg: devtools/print_wire.o
devtools/decodemsg.o: devtools/print_wire.h

devtools/mkcommit: channeld/full_channel.o channeld/commit_tx.o
devtools/mkcommit.o: channeld/full_channel.h channeld/commit_tx.h

devtools/route devtools/topology: devtools/clean_topo.o
devtools/route.o devtools/topology.o: devtools/clean_topo.h
