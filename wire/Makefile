#! /usr/bin/make

# Designed to be run one level up
wire-wrongdir:
	$(MAKE) -C .. wire-all

WIRE_HEADERS_NOGEN := wire/onion_defs.h		\
		wire/peer_wire.h		\
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
BOLT_EXTRACT=$(LOCAL_BOLTDIR)/tools/extract-formats.py

# Explicit command to re-extract CSV from BOLTs.
extract-bolt-csv: bolt-precheck
	@$(BOLT_EXTRACT) --message-fields --message-types $(LOCAL_BOLTDIR)/0[127]*.md > wire/extracted_peer_wire_csv
	@echo '#include <wire/onion_defs.h>' > wire/extracted_onion_wire_csv
	@$(BOLT_EXTRACT) --message-fields --message-types $(LOCAL_BOLTDIR)/04*.md >> wire/extracted_onion_wire_csv

# Explicit command to add diff of BOLT CSV's to an experimental_csv file
extract-experimental-bolt-csv:
	@$(BOLT_EXTRACT) --message-fields --message-types $(LOCAL_BOLTDIR)/0[127]*.md | diff -u wire/extracted_peer_wire_csv - >>wire/extracted_peer_experimental_csv | if [ $$? -lt 0 ];then exit 1;fi
	@{ echo '#include <wire/onion_defs.h>'; $(BOLT_EXTRACT) --message-fields --message-types $(LOCAL_BOLTDIR)/04*.md; } | diff -u wire/extracted_onion_wire_csv - >>wire/extracted_onion_experimental_csv | if [ $$? -lt 0 ];then exit 1;fi

wire/extracted_peer_experimental_csv:
	@touch $@

wire/extracted_onion_experimental_csv:
	@touch $@

ifeq ($(EXPERIMENTAL_FEATURES),1)
wire/gen_peer_wire_csv: wire/extracted_peer_experimental_csv wire/extracted_peer_wire_csv
	@patch --silent -o $@ wire/extracted_peer_wire_csv $<

wire/gen_onion_wire_csv: wire/extracted_onion_experimental_csv wire/extracted_onion_wire_csv
	@patch --silent -o $@ wire/extracted_onion_wire_csv $<

else # /* EXPERIMENTAL_FEATURES */
wire/gen_peer_wire_csv: wire/extracted_peer_wire_csv
	@cp $< $@

wire/gen_onion_wire_csv: wire/extracted_onion_wire_csv
	@cp $< $@
endif

wire/gen_peer_wire.h: wire/gen_peer_wire_csv $(WIRE_GEN)
	$(WIRE_GEN) --bolt --header $@ wire_type < $< > $@

wire/gen_peer_wire.c: wire/gen_peer_wire_csv $(WIRE_GEN)
	$(WIRE_GEN) --bolt ${@:.c=.h} wire_type < $< > $@

wire/gen_onion_wire.h: wire/gen_onion_wire_csv $(WIRE_GEN)
	$(WIRE_GEN) --bolt --header $@ onion_type < $< > $@

wire/gen_onion_wire.c: wire/gen_onion_wire_csv $(WIRE_GEN)
	$(WIRE_GEN) --bolt ${@:.c=.h} onion_type < $< > $@

check-source: $(WIRE_SRC:%=check-src-include-order/%) $(WIRE_HEADERS_NOGEN:%=check-hdr-include-order/%)

check-source-bolt: $(WIRE_SRC:%=bolt-check/%) $(WIRE_HEADERS_NOGEN:%=bolt-check/%)

check-whitespace: $(WIRE_SRC:%=check-whitespace/%) $(WIRE_HEADERS_NOGEN:%=check-whitespace/%) check-whitespace/wire/Makefile

clean: wire-clean

maintainer-clean: wire-maintainer-clean

wire-maintainer-clean:
	$(RM) wire/gen_*_csv wire/extracted_*_experimental_csv

wire-all: $(WIRE_OBJS) $(WIRE_ONION_OBJS)

wire-clean:
	$(RM) $(WIRE_OBJS) $(WIRE_ONION_OBJS) $(WIRE_GEN_SRC) $(WIRE_GEN_ONION_SRC) $(WIRE_GEN_HEADERS) wire/gen_*_wire_csv

include wire/test/Makefile
