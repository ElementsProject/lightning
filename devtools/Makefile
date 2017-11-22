DEVTOOLS_CLI_SRC := devtools/bolt11-cli.c
DEVTOOLS_CLI_OBJS := $(DEVTOOLS_CLI_SRC:.c=.o)

DEVTOOLS_CLI_COMMON_OBJS :=			\
	common/bech32.o				\
	common/bolt11.o				\
	common/hash_u5.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o

devtools-all: devtools/bolt11-cli

devtools/bolt11-cli: $(DEVTOOLS_CLI_OBJS) $(DEVTOOLS_CLI_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o

$(DEVTOOLS_CLI_OBJS): wire/wire.h

# Make sure these depend on everything.
ALL_PROGRAMS += devtools/bolt11-cli
ALL_OBJS += $(DEVTOOLS_CLI_OBJS)

check-source: $(DEVTOOLS_CLI_SRC:%=check-src-include-order/%)

clean: devtools-clean

devtools-clean:
	$(RM) $(DEVTOOLS_CLI_OBJS)

