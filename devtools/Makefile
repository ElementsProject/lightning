DEVTOOLS := devtools/bolt11-cli devtools/decodemsg devtools/onion devtools/dump-gossipstore devtools/gossipwith devtools/create-gossipstore devtools/mkcommit devtools/mkfunding devtools/mkclose devtools/mkgossip devtools/mkencoded devtools/mkquery devtools/lightning-checkmessage devtools/topology devtools/route devtools/bolt12-cli devtools/encodeaddr devtools/features devtools/fp16 devtools/rune
ifeq ($(HAVE_SQLITE3),1)
DEVTOOLS += devtools/checkchannels
endif

DEVTOOLS_TOOL_SRC := $(DEVTOOLS:=.c) devtools/print_wire.c devtools/clean_topo.c
DEVTOOLS_TOOL_OBJS := $(DEVTOOLS_TOOL_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(DEVTOOLS_TOOL_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += $(DEVTOOLS)

DEVTOOLS_COMMON_OBJS :=				\
	common/amount.o				\
	common/autodata.o			\
	common/blinding.o			\
	common/blindedpath.o			\
	common/coin_mvt.o			\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bolt11.o				\
	common/blockheight_states.o		\
	common/channel_id.o			\
	common/decode_array.o			\
	common/features.o			\
	common/fee_states.o			\
	common/hash_u5.o			\
	common/hmac.o				\
	common/htlc_state.o			\
	common/json_parse.o			\
	common/json_parse_simple.o		\
	common/memleak.o			\
	common/node_id.o			\
	common/per_peer_state.o			\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/sciddir_or_pubkey.o		\
	common/setup.o				\
	common/utils.o				\
	common/version.o			\
	common/wireaddr.o			\
	wire/onion_wiregen.o			\
	wire/peer_wiregen.o			\
	wire/channel_type_wiregen.o		\
	wire/tlvstream.o

devtools/features: common/features.o common/utils.o wire/fromwire.o wire/towire.o devtools/features.o

devtools/rune: common/utils.o common/autodata.o common/setup.o common/version.o wire/fromwire.o wire/towire.o devtools/rune.o

devtools/fp16: common/fp16.o common/utils.o common/setup.o common/autodata.o devtools/fp16.o

devtools/bolt11-cli: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/bolt11-cli.o

devtools/encodeaddr: common/utils.o common/bech32.o devtools/encodeaddr.o

devtools/bolt12-cli: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/bolt12_wiregen.o wire/fromwire.o wire/towire.o common/bolt12.o common/bolt12_merkle.o devtools/bolt12-cli.o common/setup.o common/iso4217.o

devtools/decodemsg: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) $(WIRE_PRINT_OBJS) wire/fromwire.o wire/towire.o devtools/print_wire.o devtools/decodemsg.o

devtools/dump-gossipstore: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/dump-gossipstore.o gossipd/gossip_store_wiregen.o

devtools/dump-gossipstore.o: gossipd/gossip_store_wiregen.h

devtools/create-gossipstore: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/create-gossipstore.o gossipd/gossip_store_wiregen.o
devtools/create-gossipstore.o: gossipd/gossip_store_wiregen.h

devtools/onion.c: ccan/config.h

devtools/onion: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) common/onion_decode.o common/onion_encode.o common/onionreply.o wire/fromwire.o wire/towire.o devtools/onion.o common/sphinx.o

devtools/gossipwith: $(DEVTOOLS_COMMON_OBJS) $(JSMN_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o wire/peer_wiregen.o devtools/gossipwith.o common/cryptomsg.o common/cryptomsg.o

$(DEVTOOLS_OBJS) $(DEVTOOLS_TOOL_OBJS): wire/wire.h

devtools/mkcommit: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) common/derive_basepoints.o common/channel_type.o common/keyset.o common/key_derive.o common/initial_commit_tx.o common/permute_tx.o wire/fromwire.o wire/towire.o devtools/mkcommit.o channeld/full_channel.o common/initial_channel.o common/htlc_state.o common/pseudorand.o common/htlc_tx.o channeld/commit_tx.o common/htlc_trim.o

devtools/mkfunding: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o common/key_derive.o devtools/mkfunding.o

devtools/mkclose: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkclose.o

devtools/mkgossip: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o common/utxo.o common/permute_tx.o common/key_derive.o devtools/mkgossip.o

devtools/mkencoded: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkencoded.o

devtools/checkchannels: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/checkchannels.o common/configdir.o common/configvar.o

devtools/mkquery: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/mkquery.o

devtools/lightning-checkmessage: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o devtools/lightning-checkmessage.o

devtools/route: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o wire/tlvstream.o common/gossmap.o common/fp16.o common/random_select.o common/route.o common/dijkstra.o devtools/clean_topo.o devtools/route.o

devtools/topology: $(DEVTOOLS_COMMON_OBJS) $(BITCOIN_OBJS) wire/fromwire.o wire/towire.o wire/tlvstream.o common/gossmap.o common/fp16.o common/random_select.o common/dijkstra.o common/route.o devtools/clean_topo.o devtools/topology.o
