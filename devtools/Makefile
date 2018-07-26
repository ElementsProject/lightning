DEVTOOLS_SRC := devtools/gen_print_wire.c devtools/gen_print_onion_wire.c devtools/print_wire.c
DEVTOOLS_OBJS := $(DEVTOOLS_SRC:.c=.o)
DEVTOOLS_TOOL_SRC := devtools/bolt11-cli.c devtools/decodemsg.c devtools/onion.c
DEVTOOLS_TOOL_OBJS := $(DEVTOOLS_TOOL_SRC:.c=.o)

DEVTOOLS_COMMON_OBJS :=				\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bolt11.o				\
	common/decode_short_channel_ids.o	\
	common/hash_u5.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o			\
	common/wireaddr.o

devtools-all: devtools/bolt11-cli devtools/decodemsg devtools/onion

devtools/gen_print_wire.h: $(WIRE_GEN) wire/gen_peer_wire_csv
	$(WIRE_GEN) --bolt --printwire --header $@ wire_type < wire/gen_peer_wire_csv > $@

devtools/gen_print_wire.c: $(WIRE_GEN) wire/gen_peer_wire_csv
	$(WIRE_GEN) --bolt --printwire ${@:.c=.h} wire_type < wire/gen_peer_wire_csv > $@

devtools/gen_print_onion_wire.h: $(WIRE_GEN) wire/gen_onion_wire_csv
	$(WIRE_GEN) --bolt --printwire --header $@ onion_type < wire/gen_onion_wire_csv > $@

devtools/gen_print_onion_wire.c: $(WIRE_GEN) wire/gen_onion_wire_csv
	$(WIRE_GEN) --bolt --printwire ${@:.c=.h} onion_type < wire/gen_onion_wire_csv > $@

devtools/bolt11-cli: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/bolt11-cli.o

devtools/decodemsg: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/decodemsg.o

devtools/onion.c: ccan/config.h

devtools/onion: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/onion.o common/sphinx.o

$(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS): wire/wire.h devtools/gen_print_wire.h devtools/gen_print_onion_wire.h
devtools/gen_print_wire.o: devtools/gen_print_wire.h wire/gen_peer_wire.h devtools/print_wire.h
devtools/gen_print_onion_wire.o: devtools/gen_print_onion_wire.h devtools/print_wire.h

# Make sure these depend on everything.
ALL_PROGRAMS += devtools/bolt11-cli devtools/decodemsg devtools/onion
ALL_OBJS += $(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS)

check-source: $(DEVTOOLS_SRC:%=check-src-include-order/%) $(DEVTOOLS_TOOLS_SRC:%=check-src-include-order/%)

clean: devtools-clean

devtools-clean:
	$(RM) $(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS) devtools/bolt11-cli devtools/decodemsg devtools/onion devtools/gen_print_wire.[c,h,o]
