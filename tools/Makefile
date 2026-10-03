#! /usr/bin/make
TOOLS_SRC := tools/lightning-hsmtool.c tools/lightning-downgrade.c
TOOLS_OBJS := $(TOOLS_SRC:%.c=$(BUILDDIR)/%.o)
TOOLS := $(TOOLS_OBJS:.o=)

# Make sure these depend on everything.
ALL_C_SOURCES += $(TOOLS_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(TOOLS)

$(TOOLS): $(BUILDDIR)/libcommon.a

$(BUILDDIR)/tools/lightning-hsmtool: $(BUILDDIR)/tools/lightning-hsmtool.o
$(BUILDDIR)/tools/lightning-downgrade.o: CFLAGS:=$(CFLAGS) -DCLN_PREV_VERSION=$(CLN_PREV_VERSION)

$(BUILDDIR)/tools/lightning-downgrade:		\
	$(addprefix $(BUILDDIR)/,		\
	db/exec.o				\
	db/bindings.o				\
	db/utils.o				\
	wallet/datastore.o			\
	wallet/migrations.o			\
	plugins/askrene/datastore_wire.o	\
	$(WALLET_DB_QUERIES:.c=.o)		\
	tools/lightning-downgrade.o		\
	)					\
	$(DB_OBJS)

update-mocks: $(tools/lightning-downgrade.c:%=update-mocks/%.c)

obsclean::
	$(RM) tools/headerversions tools/*.o

include tools/test/Makefile
