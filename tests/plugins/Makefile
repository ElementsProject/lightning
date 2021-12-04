PLUGIN_TESTLIBPLUGIN_SRC := tests/plugins/test_libplugin.c 
PLUGIN_TESTLIBPLUGIN_OBJS := $(PLUGIN_TESTLIBPLUGIN_SRC:.c=.o)

tests/plugins/test_libplugin: bitcoin/chainparams.o $(PLUGIN_TESTLIBPLUGIN_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

$(PLUGIN_TESTLIBPLUGIN_OBJS): $(PLUGIN_LIB_HEADER)

PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC := tests/plugins/test_selfdisable_after_getmanifest.c 
PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS := $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC:.c=.o)

tests/plugins/test_selfdisable_after_getmanifest: bitcoin/chainparams.o $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS) common/autodata.o common/json.o common/json_stream.o common/setup.o common/utils.o $(JSMN_OBJS) $(CCAN_OBJS)

# Make sure these depend on everything.
ALL_TEST_PROGRAMS += tests/plugins/test_libplugin tests/plugins/test_selfdisable_after_getmanifest
ALL_C_SOURCES += $(PLUGIN_TESTLIBPLUGIN_SRC) $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC)
