PLUGIN_TESTLIBPLUGIN_SRC := tests/plugins/test_libplugin.c 
PLUGIN_TESTLIBPLUGIN_OBJS := $(PLUGIN_TESTLIBPLUGIN_SRC:.c=.o)

tests/plugins/test_libplugin: bitcoin/chainparams.o $(PLUGIN_TESTLIBPLUGIN_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS)

$(PLUGIN_TESTLIBPLUGIN_OBJS): $(PLUGIN_LIB_HEADER)

PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC := tests/plugins/test_selfdisable_after_getmanifest.c 
PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS := $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC:.c=.o)

tests/plugins/test_selfdisable_after_getmanifest: bitcoin/chainparams.o $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS) common/autodata.o common/json_parse_simple.o common/setup.o common/utils.o $(JSMN_OBJS)

PLUGIN_CHANNELD_FAKENET_SRC := tests/plugins/channeld_fakenet.c 
PLUGIN_CHANNELD_FAKENET_OBJS := $(PLUGIN_CHANNELD_FAKENET_SRC:.c=.o)

tests/plugins/channeld_fakenet:			\
	$(PLUGIN_CHANNELD_FAKENET_OBJS)		\
	channeld/channeld_wiregen.o		\
	channeld/commit_tx.o			\
	bitcoin/block.o				\
	bitcoin/chainparams.o			\
	bitcoin/pubkey.o			\
	bitcoin/short_channel_id.o		\
	bitcoin/locktime.o			\
	bitcoin/preimage.o			\
	bitcoin/privkey.o			\
	bitcoin/psbt.o				\
	bitcoin/signature.o			\
	bitcoin/tx.o				\
	bitcoin/script.o			\
	bitcoin/shadouble.o			\
	bitcoin/varint.o			\
	channeld/full_channel.o			\
	channeld/inflight.o			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bigsize.o			\
	common/billboard.o			\
	common/bip32.o				\
	common/blinding.o			\
	common/blindedpath.o			\
	common/blockheight_states.o		\
	common/channel_config.o			\
	common/channel_id.o			\
	common/channel_type.o			\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/features.o			\
	common/fee_states.o			\
	common/peer_io.o			\
	common/peer_status_wiregen.o		\
	common/status_wiregen.o			\
	common/gossip_store.o			\
	common/gossmap.o			\
	common/hmac.o				\
	common/htlc_state.o			\
	common/htlc_trim.o			\
	common/htlc_tx.o			\
	common/htlc_wire.o			\
	common/initial_channel.o		\
	common/initial_commit_tx.o		\
	common/keyset.o				\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/onion_decode.o			\
	common/onionreply.o			\
	common/peer_billboard.o			\
	common/peer_failed.o			\
	common/penalty_base.o			\
	common/per_peer_state.o			\
	common/permute_tx.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/sphinx.o				\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/timeout.o			\
	common/utils.o				\
	common/version.o			\
	common/wire_error.o			\
	common/wireaddr.o			\
	common/fp16.o				\
	common/sciddir_or_pubkey.o		\
	wire/fromwire.o				\
	wire/wire_io.o				\
	wire/peer_wire.o			\
	wire/peer_wiregen.o			\
	wire/onion_wiregen.o			\
	wire/towire.o				\
	wire/channel_type_wiregen.o		\
	wire/tlvstream.o			\
	wire/wire_sync.o


# Make sure these depend on everything.
ALL_TEST_PROGRAMS += tests/plugins/test_libplugin tests/plugins/test_selfdisable_after_getmanifest tests/plugins/channeld_fakenet
ALL_C_SOURCES += $(PLUGIN_TESTLIBPLUGIN_SRC) $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC) $(PLUGIN_CHANNELD_FAKENET_SRC)
