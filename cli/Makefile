LIGHTNING_CLI_SRC := cli/lightning-cli.c
LIGHTNING_CLI_OBJS := $(LIGHTNING_CLI_SRC:.c=.o)

JSMN_OBJS := daemon/jsmn.o
JSMN_HEADERS := daemon/jsmn/jsmn.h

LIGHTNING_CLI_COMMON_OBJS :=			\
	common/configdir.o			\
	common/json.o				\
	common/version.o

lightning-cli-all: cli/lightning-cli

$(LIGHTNINGD_OPENING_OBJS): $(LIGHTNINGD_HEADERS)

# Git submodules are seriously broken.
daemon/jsmn/jsmn.h:
	git submodule update daemon/jsmn/
	[ -f $@ ] || git submodule update --init daemon/jsmn/

# If we tell Make that the above builds both, it runs it twice in
# parallel.  So we lie :(
daemon/jsmn/jsmn.c: daemon/jsmn/jsmn.h
	[ -f $@ ]

daemon/jsmn.o: daemon/jsmn/jsmn.c
	$(COMPILE.c) -DJSMN_STRICT=1 $(OUTPUT_OPTION) $<

$(LIGHTNING_CLI_OBJS) $(JSMN_OBJS): $(JSMN_HEADERS) $(COMMON_HEADERS) $(CCAN_HEADERS)

cli/lightning-cli: $(LIGHTNING_CLI_OBJS) $(LIGHTNING_CLI_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

check-source: $(LIGHTNING_CLI_SRC:%=check-src-include-order/%)

clean: lightning-cli-clean

lightning-cli-clean:
	$(RM) $(LIGHTNING-CLI_LIB_OBJS) $(DAEMON_JSMN_OBJS)

