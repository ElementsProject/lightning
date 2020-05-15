DEVTOOLS_SRC := devtools/gen_print_wire.c devtools/gen_print_onion_wire.c devtools/print_wire.c
DEVTOOLS_OBJS := $(DEVTOOLS_SRC:.c=.o)
DEVTOOLS := devtools/bolt11-cli devtools/decodemsg devtools/onion devtools/dump-gossipstore devtools/gossipwith devtools/create-gossipstore devtools/mkcommit devtools/mkfunding devtools/mkclose devtools/mkgossip devtools/mkencoded devtools/checkchannels devtools/mkquery devtools/lightning-checkmessage
ifeq ($(EXPERIMENTAL_FEATURES),1)
DEVTOOLS += devtools/blindedpath
endif

DEVTOOLS_TOOL_SRC := $(DEVTOOLS:=.c)
DEVTOOLS_TOOL_OBJS := $(DEVTOOLS_TOOL_SRC:.c=.o)

DEVTOOLS_BOLT_DEPS += $(BOLT_DEPS) tools/gen/print_impl_template tools/gen/print_header_template

DEVTOOLS_COMMON_OBJS :=				\
	common/amount.o				\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bolt11.o				\
	common/channel_id.o			\
	common/crypto_state.o			\
	common/decode_array.o			\
	common/features.o			\
	common/fee_states.o			\
	common/gossip_rcvd_filter.o		\
	common/hash_u5.o			\
	common/hmac.o				\
	common/htlc_state.o			\
	common/memleak.o			\
	common/node_id.o			\
	common/per_peer_state.o			\
	common/pseudorand.o			\
	common/json.o				\
	common/json_helpers.o			\
	common/json_stream.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o			\
	common/wireaddr.o			\
	wire/gen_onion_wire.o			\
	wire/gen_peer_wire.o

devtools-all: $(DEVTOOLS)

devtools/gen_print_wire.h: $(DEVTOOL_BOLT_DEPS) wire/gen_peer_wire_csv
	$(BOLT_GEN) -P -s --page header $@ wire_type < wire/gen_peer_wire_csv > $@

devtools/gen_print_wire.c: $(DEVTOOL_BOLT_DEPS) wire/gen_peer_wire_csv
	$(BOLT_GEN) -P -s --page impl ${@:.c=.h} wire_type < wire/gen_peer_wire_csv > $@

devtools/gen_print_onion_wire.h: $(DEVTOOL_BOLT_DEPS) wire/gen_onion_wire_csv
	$(BOLT_GEN) -P -s --page header $@ onion_type < wire/gen_onion_wire_csv > $@

devtools/gen_print_onion_wire.c: $(DEVTOOL_BOLT_DEPS) wire/gen_onion_wire_csv
	$(BOLT_GEN) -P -s --page impl ${@:.c=.h} onion_type < wire/gen_onion_wire_csv > $@

devtools/bolt11-cli: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/bolt11-cli.o

devtools/decodemsg: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/decodemsg.o

devtools/dump-gossipstore: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/dump-gossipstore.o gossipd/gen_gossip_store.o

devtools/dump-gossipstore.o: gossipd/gen_gossip_store.h

devtools/create-gossipstore: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/create-gossipstore.o gossipd/gen_gossip_store.o
devtools/create-gossipstore.o: gossipd/gen_gossip_store.h

devtools/onion.c: ccan/config.h

devtools/onion: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) common/onion.o common/onionreply.o wire/fromwire.o wire/towire.o devtools/onion.o common/sphinx.o

devtools/blindedpath: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) common/blinding.o $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/blindedpath.o common/onion.o common/onionreply.o common/sphinx.o

devtools/gossipwith: $(DEVTOOLS_OBJS) $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o wire/gen_peer_wire.o devtools/gossipwith.o common/cryptomsg.o common/cryptomsg.o common/crypto_sync.o

$(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS): wire/wire.h devtools/gen_print_wire.h devtools/gen_print_onion_wire.h
devtools/gen_print_wire.o: devtools/gen_print_wire.h wire/gen_peer_wire.h devtools/print_wire.h
devtools/gen_print_onion_wire.o: devtools/gen_print_onion_wire.h devtools/print_wire.h

devtools/mkcommit: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) common/derive_basepoints.o common/keyset.o common/key_derive.o common/initial_commit_tx.o common/permute_tx.o wire/fromwire.o wire/towire.o devtools/mkcommit.o channeld/full_channel.o common/initial_channel.o common/htlc_state.o common/pseudorand.o common/htlc_tx.o channeld/commit_tx.o common/htlc_trim.o

devtools/mkfunding: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o common/funding_tx.o common/utxo.o common/permute_tx.o common/key_derive.o devtools/mkfunding.o

devtools/mkclose: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkclose.o

devtools/mkgossip: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o common/funding_tx.o common/utxo.o common/permute_tx.o common/key_derive.o devtools/mkgossip.o

devtools/mkencoded: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkencoded.o

devtools/checkchannels: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) common/configdir.o wire/fromwire.o wire/towire.o devtools/checkchannels.o

devtools/mkquery: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkquery.o

devtools/lightning-checkmessage: $(DEVTOOLS_COMMON_OBJS) $(CCAN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/lightning-checkmessage.o

# Make sure these depend on everything.
ALL_PROGRAMS += $(DEVTOOLS)
ALL_OBJS += $(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS)

check-source: $(DEVTOOLS_SRC:%=check-src-include-order/%) $(DEVTOOLS_TOOLS_SRC:%=check-src-include-order/%)

clean: devtools-clean

devtools-clean:
	$(RM) $(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS) devtools/bolt11-cli devtools/decodemsg devtools/onion devtools/gen_print_wire.[c,h,o] devtools/gen_print_onion_wire.[c,h,o]
