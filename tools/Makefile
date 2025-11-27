#! /usr/bin/make
TOOLS := tools/lightning-hsmtool tools/lightning-downgrade
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

$(TOOLS): libcommon.a

tools/headerversions.o: ccan/config.h
tools/lightning-hsmtool: tools/lightning-hsmtool.o
tools/lightning-downgrade.o: CFLAGS:=$(CFLAGS) -DCLN_PREV_VERSION=$(CLN_PREV_VERSION)

tools/lightning-downgrade:			\
	db/exec.o				\
	db/bindings.o				\
	db/utils.o				\
	wallet/migrations.o			\
	$(DB_OBJS)				\
	$(WALLET_DB_QUERIES:.c=.o)		\
	tools/lightning-downgrade.o

update-mocks: $(tools/lightning-downgrade.c:%=update-mocks/%.c)

clean: tools-clean

tools-clean:
	$(RM) $(TOOLS) $(TOOLS_OBJ)
	$(RM) tools/headerversions
	$(RM) tools/headerversions.o

include tools/test/Makefile
