#! /usr/bin/make

# Designed to be run one level up
wire-wrongdir:
	$(MAKE) -C .. wire-all

WIRE_OBJS := wire/gen_wire.o	\
	wire/fromwire.o		\
	wire/towire.o

WIRE_HEADERS := wire/wire.h
WIRE_GEN_HEADERS := wire/gen_wire.h
WIRE_GEN_SRC := wire/gen_wire.c

# They may not have the bolts.
BOLT_EXTRACT=$(BOLTDIR)/tools/extract-formats.py
wire/gen_wire_csv: FORCE
	@set -e; if [ -f $(BOLT_EXTRACT) ]; then for f in $(BOLTDIR)/*.md $(BOLT_EXTRACT); do if [ $$f -nt $@ -o ! -f $@ ]; then $(BOLT_EXTRACT) --message-fields --message-types --check-alignment $(BOLTDIR)/*.md > $@; break; fi; done; fi

wire/gen_wire.h: wire/tools/generate-wire.py wire/gen_wire_csv
	wire/tools/generate-wire.py --header < wire/gen_wire_csv > $@

wire/gen_wire.c: wire/tools/generate-wire.py wire/gen_wire_csv
	wire/tools/generate-wire.py < wire/gen_wire_csv > $@

wire/gen_wire.o: wire/gen_wire.h

clean: wire-clean

wire-clean:
	$(RM) $(WIRE_OBJS) $(WIRE_GEN_SRC) $(WIRE_GEN_HEADERS)

include wire/test/Makefile 
