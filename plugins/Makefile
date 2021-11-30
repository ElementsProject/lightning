PLUGIN_PAY_SRC := plugins/pay.c
PLUGIN_PAY_OBJS := $(PLUGIN_PAY_SRC:.c=.o)

PLUGIN_AUTOCLEAN_SRC := plugins/autoclean.c
PLUGIN_AUTOCLEAN_OBJS := $(PLUGIN_AUTOCLEAN_SRC:.c=.o)

PLUGIN_TOPOLOGY_SRC := plugins/topology.c
PLUGIN_TOPOLOGY_OBJS := $(PLUGIN_TOPOLOGY_SRC:.c=.o)

PLUGIN_TXPREPARE_SRC := plugins/txprepare.c
PLUGIN_TXPREPARE_OBJS := $(PLUGIN_TXPREPARE_SRC:.c=.o)

PLUGIN_BCLI_SRC := plugins/bcli.c
PLUGIN_BCLI_OBJS := $(PLUGIN_BCLI_SRC:.c=.o)

PLUGIN_KEYSEND_SRC := plugins/keysend.c
PLUGIN_KEYSEND_OBJS := $(PLUGIN_KEYSEND_SRC:.c=.o)

PLUGIN_LIB_SRC := plugins/libplugin.c
PLUGIN_LIB_HEADER := plugins/libplugin.h
PLUGIN_LIB_OBJS := $(PLUGIN_LIB_SRC:.c=.o)

PLUGIN_PAY_LIB_SRC := plugins/libplugin-pay.c
PLUGIN_PAY_LIB_HEADER := plugins/libplugin-pay.h
PLUGIN_PAY_LIB_OBJS := $(PLUGIN_PAY_LIB_SRC:.c=.o)

PLUGIN_OFFERS_SRC := plugins/offers.c plugins/offers_offer.c plugins/offers_invreq_hook.c plugins/offers_inv_hook.c
PLUGIN_OFFERS_OBJS := $(PLUGIN_OFFERS_SRC:.c=.o)
PLUGIN_OFFERS_HEADER := $(PLUGIN_OFFERS_SRC:.c=.h)

PLUGIN_FETCHINVOICE_SRC := plugins/fetchinvoice.c
PLUGIN_FETCHINVOICE_OBJS := $(PLUGIN_FETCHINVOICE_SRC:.c=.o)
PLUGIN_FETCHINVOICE_HEADER := 

PLUGIN_SPENDER_SRC :=				\
	plugins/spender/fundchannel.c		\
	plugins/spender/main.c			\
	plugins/spender/multifundchannel.c	\
	plugins/spender/multiwithdraw.c		\
	plugins/spender/openchannel.c
PLUGIN_SPENDER_HEADER :=			\
	plugins/spender/multifundchannel.h	\
	plugins/spender/multiwithdraw.h		\
	plugins/spender/fundchannel.h		\
	plugins/spender/multifundchannel.h	\
	plugins/spender/openchannel.h
PLUGIN_SPENDER_OBJS := $(PLUGIN_SPENDER_SRC:.c=.o)

PLUGIN_FUNDER_SRC :=				\
	plugins/funder.c			\
	plugins/funder_policy.c
PLUGIN_FUNDER_HEADER :=				\
	plugins/funder_policy.h
PLUGIN_FUNDER_OBJS := $(PLUGIN_FUNDER_SRC:.c=.o)

PLUGIN_ALL_SRC :=				\
	$(PLUGIN_AUTOCLEAN_SRC)			\
	$(PLUGIN_BCLI_SRC)			\
	$(PLUGIN_FETCHINVOICE_SRC)		\
	$(PLUGIN_FUNDER_SRC)			\
	$(PLUGIN_TOPOLOGY_SRC)			\
	$(PLUGIN_KEYSEND_SRC)			\
	$(PLUGIN_TXPREPARE_SRC)			\
	$(PLUGIN_LIB_SRC)			\
	$(PLUGIN_OFFERS_SRC)			\
	$(PLUGIN_PAY_LIB_SRC)			\
	$(PLUGIN_PAY_SRC)			\
	$(PLUGIN_SPENDER_SRC)

PLUGIN_ALL_HEADER :=				\
	$(PLUGIN_LIB_HEADER)			\
	$(PLUGIN_FUNDER_HEADER)			\
	$(PLUGIN_PAY_LIB_HEADER)		\
	$(PLUGIN_OFFERS_HEADER)			\
	$(PLUGIN_SPENDER_HEADER)
PLUGIN_ALL_OBJS := $(PLUGIN_ALL_SRC:.c=.o)

PLUGINS :=					\
	plugins/autoclean			\
	plugins/bcli				\
	plugins/fetchinvoice			\
	plugins/funder				\
	plugins/topology			\
	plugins/keysend				\
	plugins/offers				\
	plugins/pay				\
	plugins/txprepare			\
	plugins/spenderp

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_ALL_SRC)
ALL_C_HEADERS += $(PLUGIN_ALL_HEADER)
ALL_PROGRAMS += $(PLUGINS)

PLUGIN_COMMON_OBJS :=				\
	bitcoin/base58.o			\
	bitcoin/block.o				\
	bitcoin/feerate.o			\
	bitcoin/preimage.o			\
	bitcoin/privkey.o			\
	bitcoin/psbt.o				\
	bitcoin/pubkey.o			\
	bitcoin/script.o			\
	bitcoin/shadouble.o			\
	bitcoin/short_channel_id.o		\
	bitcoin/signature.o			\
	bitcoin/tx.o				\
	bitcoin/varint.o			\
	common/amount.o				\
	common/autodata.o			\
	common/base32.o				\
	common/bech32.o				\
	common/bech32_util.o			\
	common/bigsize.o			\
	common/bolt11.o				\
	common/channel_id.o			\
	common/daemon.o				\
	common/features.o			\
	common/hash_u5.o			\
	common/json.o				\
	common/json_helpers.o			\
	common/json_stream.o			\
	common/json_tok.o			\
	common/lease_rates.o			\
	common/memleak.o			\
	common/node_id.o			\
	common/param.o				\
	common/psbt_open.o			\
	common/pseudorand.o			\
	common/random_select.o			\
	common/setup.o				\
	common/status_levels.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/version.o			\
	common/wireaddr.o			\
	wire/channel_type_wiregen.o		\
	wire/fromwire.o				\
	wire/onion$(EXP)_wiregen.o		\
	wire/peer$(EXP)_wiregen.o		\
	wire/tlvstream.o			\
	wire/towire.o

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_ALL_OBJS): $(PLUGIN_ALL_HEADER)

plugins/pay: bitcoin/chainparams.o $(PLUGIN_PAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_PAY_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) common/gossmap.o common/fp16.o common/route.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o wire/bolt12$(EXP)_wiregen.o bitcoin/block.o

plugins/autoclean: bitcoin/chainparams.o $(PLUGIN_AUTOCLEAN_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

# Topology wants to decode node_announcement, and peer_wiregen which
# pulls in some of bitcoin/.
plugins/topology: common/route.o common/dijkstra.o common/gossmap.o common/fp16.o bitcoin/chainparams.o wire/peer$(EXP)_wiregen.o wire/channel_type_wiregen.o bitcoin/block.o bitcoin/preimage.o  $(PLUGIN_TOPOLOGY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

plugins/txprepare: bitcoin/chainparams.o $(PLUGIN_TXPREPARE_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

plugins/bcli: bitcoin/chainparams.o $(PLUGIN_BCLI_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

plugins/keysend: bitcoin/chainparams.o wire/tlvstream.o wire/onion$(EXP)_wiregen.o $(PLUGIN_KEYSEND_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_PAY_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) common/gossmap.o common/fp16.o common/route.o common/dijkstra.o
$(PLUGIN_KEYSEND_OBJS): $(PLUGIN_PAY_LIB_HEADER)

plugins/spenderp: bitcoin/block.o bitcoin/chainparams.o bitcoin/preimage.o bitcoin/psbt.o common/psbt_open.o wire/peer${EXP}_wiregen.o $(PLUGIN_SPENDER_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

plugins/offers: bitcoin/chainparams.o $(PLUGIN_OFFERS_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) common/bolt12.o common/bolt12_merkle.o common/bolt11_json.o common/iso4217.o $(WIRE_OBJS) bitcoin/block.o common/channel_id.o bitcoin/preimage.o $(JSMN_OBJS) $(CCAN_OBJS)

plugins/fetchinvoice: bitcoin/chainparams.o $(PLUGIN_FETCHINVOICE_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) common/bolt12.o common/bolt12_merkle.o common/iso4217.o $(WIRE_OBJS) bitcoin/block.o common/channel_id.o bitcoin/preimage.o $(JSMN_OBJS) $(CCAN_OBJS) common/gossmap.o common/fp16.o common/dijkstra.o common/route.o common/blindedpath.o common/hmac.o common/blinding.o

plugins/funder: bitcoin/chainparams.o bitcoin/psbt.o common/psbt_open.o $(PLUGIN_FUNDER_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

# Generated from PLUGINS definition in plugins/Makefile
ALL_C_HEADERS += plugins/list_of_builtin_plugins_gen.h
plugins/list_of_builtin_plugins_gen.h: plugins/Makefile Makefile
	@$(call VERBOSE,GEN $@,echo "static const char *list_of_builtin_plugins[] = { $(foreach d,$(notdir $(PLUGINS)),\"$d\",) NULL };" > $@)

include plugins/test/Makefile
