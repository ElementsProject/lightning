#! /usr/bin/make

# Designed to be run one level up
wire-wrongdir:
	$(MAKE) -C .. wire-all

WIRE_HEADERS_NOGEN := wire/peer_wire.h		\
		wire/wire.h			\
		wire/wire_sync.h		\
		wire/wire_io.h
WIRE_GEN_HEADERS := wire/gen_peer_wire.h wire/gen_onion_wire.h
WIRE_GEN_SRC := wire/gen_peer_wire.c
WIRE_GEN_ONION_SRC := wire/gen_onion_wire.c
WIRE_SRC := wire/wire_sync.c			\
		wire/wire_io.c			\
		wire/fromwire.c			\
		wire/peer_wire.c		\
		wire/towire.c
WIRE_HEADERS := $(WIRE_HEADERS_NOGEN) $(WIRE_GEN_HEADERS)

WIRE_OBJS := $(WIRE_SRC:.c=.o) $(WIRE_GEN_SRC:.c=.o)
WIRE_ONION_OBJS := $(WIRE_GEN_ONION_SRC:.c=.o)

ALL_OBJS += $(WIRE_OBJS) $(WIRE_ONION_OBJS)
ALL_GEN_HEADERS += $(WIRE_GEN_HEADERS)

# They may not have the bolts.
BOLT_EXTRACT=$(BOLTDIR)/tools/extract-formats.py
wire/gen_peer_wire_csv: FORCE
	@set -e; if [ -f $(BOLT_EXTRACT) ]; then for f in $(BOLTDIR)/0[127]*.md $(BOLT_EXTRACT); do if [ $$f -nt $@ -o ! -f $@ ]; then $(BOLT_EXTRACT) --message-fields --message-types $(BOLTDIR)/0[127]*.md > $@; break; fi; done; fi

wire/gen_onion_wire_csv: FORCE
	@set -e; if [ -f $(BOLT_EXTRACT) ]; then for f in $(BOLTDIR)/04*.md $(BOLT_EXTRACT); do if [ $$f -nt $@ -o ! -f $@ ]; then echo '#include <wire/onion_defs.h>' > $@ && $(BOLT_EXTRACT) --message-fields --message-types $(BOLTDIR)/04*.md >> $@; break; fi; done; fi

wire/gen_peer_wire.h: $(WIRE_GEN) wire/gen_peer_wire_csv
	$(WIRE_GEN) --bolt --header $@ wire_type < wire/gen_peer_wire_csv > $@

wire/gen_peer_wire.c: $(WIRE_GEN) wire/gen_peer_wire_csv
	$(WIRE_GEN) --bolt ${@:.c=.h} wire_type < wire/gen_peer_wire_csv > $@

wire/gen_onion_wire.h: $(WIRE_GEN) wire/gen_onion_wire_csv
	$(WIRE_GEN) --bolt --header $@ onion_type < wire/gen_onion_wire_csv > $@

wire/gen_onion_wire.c: $(WIRE_GEN) wire/gen_onion_wire_csv
	$(WIRE_GEN) --bolt ${@:.c=.h} onion_type < wire/gen_onion_wire_csv > $@

check-source: $(WIRE_SRC:%=check-src-include-order/%) $(WIRE_HEADERS_NOGEN:%=check-hdr-include-order/%)

check-source-bolt: $(WIRE_SRC:%=bolt-check/%) $(WIRE_HEADERS_NOGEN:%=bolt-check/%)

check-whitespace: $(WIRE_SRC:%=check-whitespace/%) $(WIRE_HEADERS_NOGEN:%=check-whitespace/%) check-whitespace/wire/Makefile

clean: wire-clean

maintainer-clean: wire-maintainer-clean

wire-maintainer-clean:
	$(RM) wire/gen_*_csv

wire-all: $(WIRE_OBJS) $(WIRE_ONION_OBJS)

wire-clean:
	$(RM) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(WIRE_GEN_SRC) $(WIRE_GEN_ONION_SRC) $(WIRE_GEN_HEADERS)

include wire/test/Makefile
