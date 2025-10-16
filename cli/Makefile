LIGHTNING_CLI_SRC := cli/lightning-cli.c
LIGHTNING_CLI_OBJS := $(LIGHTNING_CLI_SRC:.c=.o)

ALL_C_SOURCES += $(LIGHTNING_CLI_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += cli/lightning-cli

$(LIGHTNING_CLI_OBJS): $(JSMN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS)

cli/lightning-cli: $(LIGHTNING_CLI_OBJS) $(JSMN_OBJS) libcommon.a libccan.a

include cli/test/Makefile
