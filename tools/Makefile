#! /usr/bin/make
TOOLS := tools/hsmtool tools/check-bolt
TOOLS_SRC := $(TOOLS:=.c)
TOOLS_OBJ := $(TOOLS_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(TOOLS_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(TOOLS)

TOOLS_COMMON_OBJS = common/utils.o

# We force make to relink this every time, to detect version changes.
# Do it atomically, otherwise parallel builds can get upset!
tools/headerversions: $(FORCE) tools/headerversions.o libccan.a
	@trap "rm -f $@.tmp.$$$$" EXIT; $(LINK.o) tools/headerversions.o libccan.a $(LOADLIBES) $(LDLIBS) -o $@.tmp.$$$$ && mv $@.tmp.$$$$ $@

tools/headerversions.o: ccan/config.h
tools/check-bolt: tools/check-bolt.o $(TOOLS_COMMON_OBJS)

tools/hsmtool: tools/hsmtool.o $(TOOLS_COMMON_OBJS) $(BITCOIN_OBJS) common/amount.o common/autodata.o common/bech32.o common/bech32_util.o common/bigsize.o common/codex32.o common/configdir.o common/configvar.o common/derive_basepoints.o common/descriptor_checksum.o common/hsm_encryption.o common/node_id.o common/version.o wire/fromwire.o wire/towire.o

tools/lightning-hsmtool: tools/hsmtool
	cp $< $@

clean: tools-clean

tools-clean:
	$(RM) tools/headerversions
	$(RM) tools/headerversions.o

include tools/test/Makefile
