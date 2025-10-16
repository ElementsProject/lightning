PLUGIN_XPAY_SRC :=				\
	plugins/xpay/xpay.c

PLUGIN_XPAY_HDRS :=

PLUGIN_XPAY_OBJS := $(PLUGIN_XPAY_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_XPAY_SRC)
ALL_C_HEADERS += $(PLUGIN_XPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity.
$(PLUGIN_XPAY_OBJS): $(PLUGIN_XPAY_HDRS)

plugins/cln-xpay: $(PLUGIN_XPAY_OBJS) $(PLUGIN_LIB_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) libcommon.a
