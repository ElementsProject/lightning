#! /usr/bin/make
TOOLS := tools/hsmtool tools/check-bolt
TOOLS_SRC := $(TOOLS:=.c)
TOOLS_OBJ := $(TOOLS_SRC:.c=.o)
ALL_PROGRAMS += $(TOOLS)
ALL_OBJS += $(TOOLS_OBJ)

TOOLS_COMMON_OBJS = common/utils.o

# We force make to relink this every time, to detect version changes.
# Do it atomically, otherwise parallel builds can get upset!
tools/headerversions: FORCE tools/headerversions.o $(CCAN_OBJS)
	@trap "rm -f $@.tmp.$$$$" EXIT; $(LINK.o) tools/headerversions.o $(CCAN_OBJS) $(LOADLIBES) $(LDLIBS) -o $@.tmp.$$$$ && mv $@.tmp.$$$$ $@

tools/check-bolt: tools/check-bolt.o $(CCAN_OBJS) $(TOOLS_COMMON_OBJS)

tools/hsmtool: tools/hsmtool.o $(CCAN_OBJS) $(TOOLS_COMMON_OBJS) $(BITCOIN_OBJS) common/amount.o common/bech32.o common/bigsize.o common/derive_basepoints.o common/node_id.o common/type_to_string.o wire/fromwire.o wire/towire.o

tools/lightning-hsmtool: tools/hsmtool
	cp $< $@

clean: tools-clean

tools-clean:
	$(RM) tools/check-bolt tools/*.o
	$(RM) tools/headerversions
	$(RM) $(TOOLS_OBJ) $(TOOLS) tools/lightning-hsmtool

include tools/test/Makefile
