#! /usr/bin/make
TOOLS := tools/lightning-hsmtool
TOOLS_SRC := $(TOOLS:=.c)
TOOLS_OBJ := $(TOOLS_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(TOOLS_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(TOOLS)

# We force make to relink this every time, to detect version changes.
# Do it atomically, otherwise parallel builds can get upset!
tools/headerversions: $(FORCE) tools/headerversions.o libccan.a
	@trap "rm -f $@.tmp.$$$$" EXIT; $(LINK.o) tools/headerversions.o libccan.a $(LOADLIBES) $(LDLIBS) -o $@.tmp.$$$$ && mv -f $@.tmp.$$$$ $@

tools/headerversions.o: ccan/config.h
tools/lightning-hsmtool: tools/lightning-hsmtool.o libcommon.a

clean: tools-clean

tools-clean:
	$(RM) $(TOOLS) $(TOOLS_OBJ)
	$(RM) tools/headerversions
	$(RM) tools/headerversions.o

include tools/test/Makefile
