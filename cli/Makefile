LIGHTNING_CLI_SRC := cli/lightning-cli.c
LIGHTNING_CLI_OBJS := $(LIGHTNING_CLI_SRC:.c=.o)

LIGHTNING_CLI_COMMON_OBJS :=			\
	common/configdir.o			\
	common/json.o				\
	common/json_escaped.o			\
	common/utils.o			\
	common/version.o

lightning-cli-all: cli/lightning-cli

$(LIGHTNINGD_OPENING_OBJS): $(LIGHTNINGD_HEADERS) $(EXTERNAL_HEADERS)

$(LIGHTNING_CLI_OBJS) $(JSMN_OBJS): $(JSMN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS)

cli/lightning-cli: $(LIGHTNING_CLI_OBJS) $(LIGHTNING_CLI_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

# Make sure these depend on everything.
ALL_PROGRAMS += cli/lightning-cli
ALL_OBJS += $(LIGHTNING_CLI_OBJS)

check-source: $(LIGHTNING_CLI_SRC:%=check-src-include-order/%)

clean: lightning-cli-clean

lightning-cli-clean:
	$(RM) $(LIGHTNING-CLI_LIB_OBJS) $(DAEMON_JSMN_OBJS)

include cli/test/Makefile
