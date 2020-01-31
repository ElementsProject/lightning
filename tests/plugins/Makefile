PLUGIN_TESTLIBPLUGIN_SRC := tests/plugins/test_libplugin.c
PLUGIN_TESTLIBPLUGIN_OBJS := $(PLUGIN_TESTLIBPLUGIN_SRC:.c=.o)

tests/plugins/test_libplugin: bitcoin/chainparams.o $(PLUGIN_TESTLIBPLUGIN_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

$(PLUGIN_TESTLIBPLUGIN_OBJS): $(PLUGIN_LIB_HEADER)

# Make sure these depend on everything.
ALL_PROGRAMS += tests/plugins/test_libplugin
ALL_OBJS += $(PLUGIN_TESTLIBPLUGIN_OBJS)

check-source: $(PLUGIN_TESTLIBPLUGIN_SRC:%=check-src-include-order/%)
check-whitespace: $(PLUGIN_TESTLIBPLUGIN_SRC:%=check-whitespace/%)

clean: test-plugin-clean

test-plugin-clean:
	$(RM) $(PLUGIN_TESTLIBPLUGIN_OBJS)
