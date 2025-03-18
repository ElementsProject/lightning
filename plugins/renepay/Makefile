PLUGIN_RENEPAY_SRC :=				\
	plugins/renepay/renepay.c		\
	plugins/renepay/payment.c		\
	plugins/renepay/route.c			\
	plugins/renepay/routetracker.c		\
	plugins/renepay/routefail.c		\
	plugins/renepay/sendpay.c		\
	plugins/renepay/mods.c			\
	plugins/renepay/errorcodes.c		\
	plugins/renepay/utils.c			\
	plugins/renepay/json.c

PLUGIN_RENEPAY_HDRS :=				\
	plugins/renepay/renepay.h		\
	plugins/renepay/payment.h		\
	plugins/renepay/payment_info.h		\
	plugins/renepay/renepayconfig.h		\
	plugins/renepay/route.h			\
	plugins/renepay/routetracker.h		\
	plugins/renepay/routefail.h		\
	plugins/renepay/sendpay.h		\
	plugins/renepay/mods.h			\
	plugins/renepay/errorcodes.h		\
	plugins/renepay/utils.h			\
	plugins/renepay/json.c

PLUGIN_RENEPAY_OBJS := $(PLUGIN_RENEPAY_SRC:.c=.o)

# Make sure these depend on everything.
PLUGIN_ALL_SRC += $(PLUGIN_RENEPAY_SRC)
PLUGIN_ALL_HEADER += $(PLUGIN_RENEPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_RENEPAY_OBJS): $(PLUGIN_RENEPAY_HDRS)

plugins/cln-renepay: $(PLUGIN_RENEPAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) bitcoin/chainparams.o common/gossmap.o common/gossmods_listpeerchannels.o common/fp16.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o common/sciddir_or_pubkey.o wire/bolt12_wiregen.o wire/onion_wiregen.o common/sphinx.o common/onion_encode.o common/hmac.o common/onionreply.o

include plugins/renepay/test/Makefile
