#! /usr/bin/make

# Designed to be run one level up
wire-wrongdir:
	$(MAKE) -C .. wire-all

WIRE_HEADERS_NOGEN := wire/onion_defs.h		\
		wire/peer_wire.h		\
		wire/tlvstream.h			\
		wire/wire.h			\
		wire/wire_sync.h		\
		wire/wire_io.h
WIRE_GEN_HEADERS := wire/peer_wiregen.h		\
		wire/onion_wiregen.h		\
		wire/common_wiregen.h		\
		wire/peer_printgen.h		\
		wire/onion_printgen.h

WIRE_GEN_SRC := wire/peer_wiregen.c wire/common_wiregen.c
WIRE_GEN_ONION_SRC := wire/onion_wiregen.c
WIRE_GEN_PRINT_SRC := wire/peer_printgen.c wire/onion_printgen.c

WIRE_SRC := wire/wire_sync.c			\
		wire/wire_io.c			\
		wire/fromwire.c			\
		wire/peer_wire.c		\
		wire/tlvstream.c		\
		wire/towire.c
WIRE_HEADERS := $(WIRE_HEADERS_NOGEN) $(WIRE_GEN_HEADERS)

WIRE_OBJS := $(WIRE_SRC:.c=.o) $(WIRE_GEN_SRC:.c=.o)
WIRE_ONION_OBJS := $(WIRE_GEN_ONION_SRC:.c=.o)

ALL_OBJS += $(WIRE_OBJS) $(WIRE_ONION_OBJS)
ALL_GEN_HEADERS += $(WIRE_GEN_HEADERS)

# They may not have the bolts.
BOLT_EXTRACT=$(LOCAL_BOLTDIR)/tools/extract-formats.py

WIRE_BOLT_DEPS := $(BOLT_DEPS) tools/gen/impl_template tools/gen/header_template

# Explicit command to re-extract CSV from BOLTs.
extract-bolt-csv: bolt-precheck
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/0[127]*.md > wire/extracted_peer_wire_csv
	@echo '#include <wire/onion_defs.h>' > wire/extracted_onion_wire_csv
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/04*.md >> wire/extracted_onion_wire_csv

# Explicit command to add patchfile for BOLT CSV's
extract-experimental-bolt-csv: bolt-precheck
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/0[127]*.md | diff -u wire/extracted_peer_wire_csv - >wire/extracted_peer_experimental_$(BOLTVERSION) | if [ $$? -lt 0 ];then exit 1;fi
	@{ echo '#include <wire/onion_defs.h>'; $(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/04*.md; } | diff -u wire/extracted_onion_wire_csv - > wire/extracted_onion_experimental_$(BOLTVERSION) | if [ $$? -lt 0 ];then exit 1;fi

wire/extracted_peer_experimental_csv:
	@touch $@

wire/extracted_onion_experimental_csv:
	@touch $@

ifeq ($(EXPERIMENTAL_FEATURES),1)
EXPERIMENTAL_PEER_PATCHES := $(sort $(wildcard wire/extracted_peer_experimental_*))
EXPERIMENTAL_ONION_PATCHES := $(sort $(wildcard wire/extracted_onion_experimental_*))

wire/peer_wire.csv: wire/extracted_peer_wire_csv $(EXPERIMENTAL_PEER_PATCHES)
	@set -e; trap "rm -f $@.$$$$" 0; cp $< $@.$$$$; for exp in $(EXPERIMENTAL_PEER_PATCHES); do patch $@.$$$$ $$exp >/dev/null ; done; mv $@.$$$$ $@

wire/onion_wire.csv: wire/extracted_onion_wire_csv $(EXPERIMENTAL_ONION_PATCHES)
	@set -e; trap "rm -f $@.$$$$" 0; cp $< $@.$$$$; for exp in $(EXPERIMENTAL_ONION_PATCHES); do patch $@.$$$$ $$exp; done >/dev/null ; mv $@.$$$$ $@

else # /* EXPERIMENTAL_FEATURES */
wire/peer_wire.csv: wire/extracted_peer_wire_csv
	@cp $< $@

wire/onion_wire.csv: wire/extracted_onion_wire_csv
	@cp $< $@
endif

# We (may) need to rebuild these if config changes
wire/peer_wire.csv wire/onion_wire.csv: config.vars

# tlvs_n1 and n2 are used for test vectors, thus not referenced: expose them
# for testing and to prevent compile error about them being unused.
# This will be easier if test vectors are moved to separate files.
wire/peer_wiregen.h_args := --include='common/channel_id.h' --include='bitcoin/tx.h' --include='bitcoin/preimage.h' --include='bitcoin/short_channel_id.h' --include='common/node_id.h' --include='common/bigsize.h' --include='bitcoin/block.h' --include='bitcoin/privkey.h' -s --expose-tlv-type=n1 --expose-tlv-type=n2

wire/peer_wiregen.c_args := -s --expose-tlv-type=n1 --expose-tlv-type=n2

# The tlv_payload isn't parsed in a fromwire, so we need to expose it.
wire/onion_wiregen.h_args := --include='bitcoin/short_channel_id.h' --include='bitcoin/privkey.h' --include='common/bigsize.h' --include='common/amount.h' --include='common/node_id.h' --include='bitcoin/block.h' -s --expose-tlv-type=tlv_payload

wire/onion_wiregen.c_args := -s --expose-tlv-type=tlv_payload

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
