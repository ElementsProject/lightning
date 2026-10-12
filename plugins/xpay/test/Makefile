# Note that these actually #include everything they need, except ccan/, bitcoin/ and wire/.
PLUGIN_XPAY_TEST_SRC := $(wildcard plugins/xpay/test/run-*.c)
PLUGIN_XPAY_TEST_OBJS := $(PLUGIN_XPAY_TEST_SRC:.c=.o)
PLUGIN_XPAY_TEST_PROGRAMS := $(PLUGIN_XPAY_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_XPAY_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_XPAY_TEST_PROGRAMS)

$(PLUGIN_XPAY_TEST_OBJS): $(PLUGIN_XPAY_SRC) $(PLUGIN_XPAY_HDRS) plugins/xpay/test/Makefile

$(PLUGIN_XPAY_TEST_PROGRAMS): libcommon.a

check-xpay: $(PLUGIN_XPAY_TEST_PROGRAMS:%=unittest/%)

check-units: check-xpay
