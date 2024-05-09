PLUGIN_RENEPAY_SRC :=				\
	plugins/renepay/main.c			\
	plugins/renepay/flow.c			\
	plugins/renepay/mcf.c			\
	plugins/renepay/dijkstra.c		\
	plugins/renepay/disabledmap.c		\
	plugins/renepay/payment.c		\
	plugins/renepay/chan_extra.c		\
	plugins/renepay/route.c			\
	plugins/renepay/routebuilder.c		\
	plugins/renepay/routetracker.c		\
	plugins/renepay/routefail.c		\
	plugins/renepay/uncertainty.c		\
	plugins/renepay/mods.c			\
	plugins/renepay/errorcodes.c		\
	plugins/renepay/json.c

PLUGIN_RENEPAY_HDRS :=				\
	plugins/renepay/payplugin.h		\
	plugins/renepay/flow.h			\
	plugins/renepay/mcf.h			\
	plugins/renepay/dijkstra.h		\
	plugins/renepay/disabledmap.h		\
	plugins/renepay/payment.h		\
	plugins/renepay/payment_info.h		\
	plugins/renepay/chan_extra.h		\
	plugins/renepay/route.h			\
	plugins/renepay/routebuilder.h		\
	plugins/renepay/routetracker.h		\
	plugins/renepay/routefail.h		\
	plugins/renepay/uncertainty.h		\
	plugins/renepay/mods.h			\
	plugins/renepay/errorcodes.h		\
	plugins/renepay/json.c

PLUGIN_RENEPAY_OBJS := $(PLUGIN_RENEPAY_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_RENEPAY_SRC)
ALL_C_HEADERS += $(PLUGIN_RENEPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_RENEPAY_OBJS): $(PLUGIN_RENEPAY_HDRS)

plugins/cln-renepay: $(PLUGIN_RENEPAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) bitcoin/chainparams.o common/gossmap.o common/gossmods_listpeerchannels.o common/fp16.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o common/sciddir_or_pubkey.o wire/bolt12_wiregen.o wire/onion_wiregen.o

include plugins/renepay/test/Makefile
