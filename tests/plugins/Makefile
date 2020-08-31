PLUGIN_TESTLIBPLUGIN_SRC := tests/plugins/test_libplugin.c
PLUGIN_TESTLIBPLUGIN_OBJS := $(PLUGIN_TESTLIBPLUGIN_SRC:.c=.o)

tests/plugins/test_libplugin: bitcoin/chainparams.o $(PLUGIN_TESTLIBPLUGIN_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

$(PLUGIN_TESTLIBPLUGIN_OBJS): $(PLUGIN_LIB_HEADER)

# Make sure these depend on everything.
ALL_TEST_PROGRAMS += tests/plugins/test_libplugin
ALL_C_SOURCES += $(PLUGIN_TESTLIBPLUGIN_SRC)
