# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
PLUGIN_RENEPAY_TEST_SRC := $(wildcard plugins/renepay/test/run-*.c)
PLUGIN_RENEPAY_TEST_OBJS := $(PLUGIN_RENEPAY_TEST_SRC:.c=.o)
PLUGIN_RENEPAY_TEST_PROGRAMS := $(PLUGIN_RENEPAY_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_RENEPAY_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_RENEPAY_TEST_PROGRAMS)
$(PLUGIN_RENEPAY_TEST_OBJS): $(PLUGIN_RENEPAY_SRC) plugins/renepay/test/common.h plugins/renepay/test/Makefile

$(PLUGIN_RENEPAY_TEST_PROGRAMS):		\
	plugins/renepay/dijkstra.o		\
	plugins/renepay/chan_extra.o		\
	gossipd/gossip_store_wiregen.o		\
	libcommon.a

check-renepay: $(PLUGIN_RENEPAY_TEST_PROGRAMS:%=unittest/%)

check-units: check-renepay
