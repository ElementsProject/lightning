PLUGIN_REPEATPAY_SRC :=				\
	plugins/repeatpay/repeatpay.c

PLUGIN_REPEATPAY_HDRS :=

PLUGIN_REPEATPAY_OBJS := $(PLUGIN_REPEATPAY_SRC:.c=.o)

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_REPEATPAY_SRC)
ALL_C_HEADERS += $(PLUGIN_REPEATPAY_HDRS)

# Make all plugins depend on all plugin headers, for simplicity (and this file)
$(PLUGIN_REPEATPAY_OBJS): $(PLUGIN_REPEATPAY_HDRS) plugins/repeatpay/Makefile

plugins/cln-repeatpay: $(PLUGIN_REPEATPAY_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a
