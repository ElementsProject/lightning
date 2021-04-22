# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
PLUGIN_TEST_SRC := $(wildcard plugins/test/run-*.c)
PLUGIN_TEST_OBJS := $(PLUGIN_TEST_SRC:.c=.o)
PLUGIN_TEST_PROGRAMS := $(PLUGIN_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN__TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_TEST_PROGRAMS)

PLUGIN_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/pseudorand.o			\
	common/setup.o				\
	common/type_to_string.o			\
	common/utils.o

update-mocks: $(PLUGIN_TEST_SRC:%=update-mocks/%)

$(PLUGIN_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(PLUGIN_TEST_COMMON_OBJS)

$(PLUGIN_TEST_OBJS): $(PLUGIN_FUNDER_HEADER) $(PLUGIN_FUNDER_SRC)

check-units: $(PLUGIN_TEST_PROGRAMS:%=unittest/%)
