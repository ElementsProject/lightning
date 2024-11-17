PLUGIN_XPAY_SRC :=				\
	plugins/xpay/xpay.c

PLUGIN_XPAY_HDRS :=

PLUGIN_XPAY_OBJS := $(PLUGIN_XPAY_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_XPAY_SRC)
ALL_C_HEADERS += $(PLUGIN_XPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_XPAY_OBJS): $(PLUGIN_XPAY_HDRS)

plugins/cln-xpay: $(PLUGIN_XPAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) bitcoin/chainparams.o common/gossmap.o common/gossmods_listpeerchannels.o common/fp16.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o common/sciddir_or_pubkey.o wire/bolt12_wiregen.o wire/onion_wiregen.o common/onionreply.o common/onion_encode.o common/sphinx.o common/hmac.o
