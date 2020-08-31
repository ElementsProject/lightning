#! /usr/bin/make

WIRE_HEADERS :=	wire/onion_defs.h		\
		wire/peer_wire.h		\
		wire/tlvstream.h		\
		wire/wire.h			\
		wire/wire_sync.h		\
		wire/wire_io.h			\
		wire/peer_wiregen.h		\
		wire/onion_wiregen.h		\
		wire/common_wiregen.h		\
		wire/peer_printgen.h		\
		wire/onion_printgen.h

# We don't include peer_printgen/onion_printgen here since most don't need it.
WIRE_SRC := wire/wire_sync.c			\
		wire/wire_io.c			\
		wire/fromwire.c			\
		wire/peer_wire.c		\
		wire/tlvstream.c		\
		wire/towire.c			\
		wire/common_wiregen.c		\
		wire/peer_wiregen.c		\
		wire/onion_wiregen.c	

WIRE_PRINT_SRC :=				\
		wire/onion_printgen.c		\
		wire/peer_printgen.c

WIRE_OBJS := $(WIRE_SRC:.c=.o)
WIRE_PRINT_OBJS := $(WIRE_PRINT_SRC:.c=.o)
$(WIRE_OBJS) $(WIRE_PRINT_OBJS): $(WIRE_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(WIRE_SRC) $(WIRE_PRINT_SRC)
ALL_C_HEADERS += $(WIRE_HEADERS)

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

maintainer-clean: wire-maintainer-clean

wire-maintainer-clean:
	$(RM) wire/gen_*_csv wire/extracted_*_experimental_csv

include wire/test/Makefile
