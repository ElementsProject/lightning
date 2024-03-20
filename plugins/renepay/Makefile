PLUGIN_RENEPAY_SRC := plugins/renepay/pay.c plugins/renepay/pay_flow.c plugins/renepay/flow.c plugins/renepay/mcf.c plugins/renepay/dijkstra.c \
	plugins/renepay/payment.c plugins/renepay/uncertainty_network.c
PLUGIN_RENEPAY_HDRS := plugins/renepay/pay.h plugins/renepay/pay_flow.h plugins/renepay/flow.h plugins/renepay/mcf.h plugins/renepay/dijkstra.h \
	plugins/renepay/payment.h plugins/renepay/uncertainty_network.h
PLUGIN_RENEPAY_OBJS := $(PLUGIN_RENEPAY_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_RENEPAY_SRC)
ALL_C_HEADERS += $(PLUGIN_RENEPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_RENEPAY_OBJS): $(PLUGIN_RENEPAY_HDRS)

plugins/cln-renepay: $(PLUGIN_RENEPAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) bitcoin/chainparams.o common/gossmap.o common/gossmods_listpeerchannels.o common/fp16.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o wire/bolt12$(EXP)_wiregen.o wire/onion_wiregen.o

include plugins/renepay/test/Makefile
