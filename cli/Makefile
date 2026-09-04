LIGHTNING_CLI_SRC := cli/lightning-cli.c
LIGHTNING_CLI_OBJS := $(LIGHTNING_CLI_SRC:%.c=$(BUILDDIR)/%.o)

ALL_C_SOURCES += $(LIGHTNING_CLI_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(BUILDDIR)/cli/lightning-cli

$(LIGHTNING_CLI_OBJS): cli/Makefile

$(BUILDDIR)/cli/lightning-cli: $(LIGHTNING_CLI_OBJS) $(BUILDDIR)/libcommon.a

obsclean::
	$(RM) cli/*.o

include cli/test/Makefile
