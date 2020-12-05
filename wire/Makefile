#! /usr/bin/make

WIRE_HEADERS :=	wire/onion_defs.h		\
		wire/peer_wire.h		\
		wire/onion_wire.h		\
		wire/tlvstream.h		\
		wire/wire.h			\
		wire/wire_sync.h		\
		wire/wire_io.h			\
		wire/peer$(EXP)_wiregen.h	\
		wire/onion$(EXP)_wiregen.h	\
		wire/common_wiregen.h		\
		wire/peer$(EXP)_printgen.h	\
		wire/onion$(EXP)_printgen.h

# We don't include peer_printgen/onion_printgen here since most don't need it.
WIRE_SRC := wire/wire_sync.c			\
		wire/wire_io.c			\
		wire/wire_dummy.c		\
		wire/fromwire.c			\
		wire/peer_wire.c		\
		wire/tlvstream.c		\
		wire/towire.c			\
		wire/common_wiregen.c		\
		wire/peer$(EXP)_wiregen.c	\
		wire/onion$(EXP)_wiregen.c	

WIRE_PRINT_SRC :=				\
		wire/onion$(EXP)_printgen.c	\
		wire/peer$(EXP)_printgen.c

ifeq ($(EXPERIMENTAL_FEATURES),1)
WIRE_HEADERS += wire/bolt12$(EXP)_wiregen.h
WIRE_SRC += wire/bolt12$(EXP)_wiregen.c
endif

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
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/0[127]*.md > wire/peer_wire.csv
	@echo '#include <wire/onion_defs.h>' > wire/onion_wire.csv
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/04*.md >> wire/onion_wire.csv

extract-bolt12-csv: bolt-precheck
	$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/12*.md > wire/bolt12_exp_wire.csv

ifeq ($(EXPERIMENTAL_FEATURES),1)
extract-bolt-csv: extract-bolt12-csv
endif

# Explicit command to add patchfile for BOLT CSV's
extract-experimental-bolt-csv: bolt-precheck
	@$(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/0[127]*.md | diff -u wire/peer_exp_wire.csv - >wire/extracted_peer_experimental_$(BOLTVERSION) | if [ $$? -lt 0 ];then exit 1;fi
	@{ echo '#include <wire/onion_defs.h>'; $(BOLT_EXTRACT) $(LOCAL_BOLTDIR)/04*.md; } | diff -u wire/onion_exp_wire.csv - > wire/extracted_onion_experimental_$(BOLTVERSION) | if [ $$? -lt 0 ];then exit 1;fi

ifeq ($(EXPERIMENTAL_FEATURES),1)
EXPERIMENTAL_PEER_PATCHES := $(sort $(wildcard wire/extracted_peer_experimental_*))
EXPERIMENTAL_ONION_PATCHES := $(sort $(wildcard wire/extracted_onion_experimental_*))

wire/peer_exp_wire.csv: wire/peer_wire.csv $(EXPERIMENTAL_PEER_PATCHES)
	@set -e; trap "rm -f $@.$$$$" 0; cp $< $@.$$$$; for exp in $(EXPERIMENTAL_PEER_PATCHES); do patch $@.$$$$ $$exp >/dev/null ; done; mv $@.$$$$ $@

wire/onion_exp_wire.csv: wire/onion_wire.csv $(EXPERIMENTAL_ONION_PATCHES)
	@set -e; trap "rm -f $@.$$$$" 0; cp $< $@.$$$$; for exp in $(EXPERIMENTAL_ONION_PATCHES); do patch $@.$$$$ $$exp; done >/dev/null ; mv $@.$$$$ $@
endif

# tlvs_n1 and n2 are used for test vectors, thus not referenced: expose them
# for testing and to prevent compile error about them being unused.
# This will be easier if test vectors are moved to separate files.
wire/peer_wiregen.h_args := --include='common/channel_id.h' --include='bitcoin/tx.h' --include='bitcoin/preimage.h' --include='bitcoin/short_channel_id.h' --include='common/node_id.h' --include='common/bigsize.h' --include='bitcoin/block.h' --include='bitcoin/privkey.h' -s --expose-tlv-type=n1 --expose-tlv-type=n2

wire/peer_wiregen.c_args := -s --expose-tlv-type=n1 --expose-tlv-type=n2

# The tlv_payload isn't parsed in a fromwire, so we need to expose it.
wire/onion_wiregen.h_args := --include='bitcoin/short_channel_id.h' --include='bitcoin/privkey.h' --include='common/bigsize.h' --include='common/amount.h' --include='common/node_id.h' --include='bitcoin/block.h' -s --expose-tlv-type=tlv_payload

wire/onion_wiregen.c_args := -s --expose-tlv-type=tlv_payload

# Same for _exp versions
wire/peer_exp_wiregen.h_args := $(wire/peer_wiregen.h_args)
wire/peer_exp_wiregen.c_args := $(wire/peer_wiregen.c_args)
wire/onion_exp_wiregen.h_args := $(wire/onion_wiregen.h_args)
wire/onion_exp_wiregen.c_args := $(wire/onion_wiregen.c_args)

wire/bolt12_exp_wiregen.c_args := -s --expose-tlv-type=blinded_path
wire/bolt12_exp_wiregen.h_args := --include='bitcoin/short_channel_id.h' --include='bitcoin/signature.h' --include='bitcoin/privkey.h' --include='common/bigsize.h' --include='common/amount.h' --include='common/node_id.h' --include='bitcoin/block.h'  --include='wire/onion_wire.h' $(wire/bolt12_exp_wiregen.c_args)

wire/peer_wiregen.h_args := --include='common/channel_id.h' --include='bitcoin/tx.h' --include='bitcoin/preimage.h' --include='bitcoin/short_channel_id.h' --include='common/node_id.h' --include='common/bigsize.h' --include='bitcoin/block.h' --include='bitcoin/privkey.h' -s --expose-tlv-type=n1 --expose-tlv-type=n2

maintainer-clean: wire-maintainer-clean

wire-maintainer-clean:
	$(RM) wire/gen_*_csv wire/extracted_*_experimental_csv

include wire/test/Makefile
