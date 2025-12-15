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
	plugins/renepay/sendpay.c		\
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
	plugins/renepay/renepayconfig.h		\
	plugins/renepay/route.h			\
	plugins/renepay/routebuilder.h		\
	plugins/renepay/routetracker.h		\
	plugins/renepay/routefail.h		\
	plugins/renepay/sendpay.h		\
	plugins/renepay/uncertainty.h		\
	plugins/renepay/mods.h			\
	plugins/renepay/errorcodes.h		\
	plugins/renepay/json.h

PLUGIN_RENEPAY_OBJS := $(PLUGIN_RENEPAY_SRC:.c=.o)

# Make sure these depend on everything.
PLUGIN_ALL_SRC += $(PLUGIN_RENEPAY_SRC)
PLUGIN_ALL_HEADER += $(PLUGIN_RENEPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity (and this file).
$(PLUGIN_RENEPAY_OBJS): $(PLUGIN_RENEPAY_HDRS) plugins/renepay/Makefile

plugins/cln-renepay: $(PLUGIN_RENEPAY_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

include plugins/renepay/test/Makefile
