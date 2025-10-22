PLUGIN_TESTLIBPLUGIN_SRC := tests/plugins/test_libplugin.c 
PLUGIN_TESTLIBPLUGIN_OBJS := $(PLUGIN_TESTLIBPLUGIN_SRC:.c=.o)

tests/plugins/test_libplugin: $(PLUGIN_TESTLIBPLUGIN_OBJS) $(PLUGIN_LIB_OBJS) $(JSMN_OBJS) libcommon.a

$(PLUGIN_TESTLIBPLUGIN_OBJS): $(PLUGIN_LIB_HEADER)

PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC := tests/plugins/test_selfdisable_after_getmanifest.c 
PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS := $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC:.c=.o)

tests/plugins/test_selfdisable_after_getmanifest: $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_OBJS) $(JSMN_OBJS) libcommon.a

PLUGIN_CHANNELD_FAKENET_SRC := tests/plugins/channeld_fakenet.c 
PLUGIN_CHANNELD_FAKENET_OBJS := $(PLUGIN_CHANNELD_FAKENET_SRC:.c=.o)

tests/plugins/channeld_fakenet:			\
	$(PLUGIN_CHANNELD_FAKENET_OBJS)		\
	channeld/channeld_wiregen.o		\
	channeld/commit_tx.o			\
	channeld/full_channel.o			\
	channeld/inflight.o			\
	libcommon.a

# Make sure these depend on everything.
ALL_TEST_PROGRAMS += tests/plugins/test_libplugin tests/plugins/test_selfdisable_after_getmanifest tests/plugins/channeld_fakenet
ALL_C_SOURCES += $(PLUGIN_TESTLIBPLUGIN_SRC) $(PLUGIN_TESTSELFDISABLE_AFTER_GETMANIFEST_SRC) $(PLUGIN_CHANNELD_FAKENET_SRC)
