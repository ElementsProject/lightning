# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CONNECTD_TEST_SRC := $(wildcard connectd/test/run-*.c)
CONNECTD_TEST_OBJS := $(CONNECTD_TEST_SRC:.c=.o)
CONNECTD_TEST_PROGRAMS := $(CONNECTD_TEST_OBJS:.o=)

CONNECTD_TEST_COMMON_OBJS :=			\
	common/autodata.o			\
	common/features.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/utils.o

ALL_C_SOURCES += $(CONNECTD_TEST_SRC)
ALL_TEST_PROGRAMS += $(CONNECTD_TEST_PROGRAMS)

$(CONNECTD_TEST_PROGRAMS): $(CONNECTD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(CONNECTD_TEST_OBJS): $(CONNECTD_HEADERS) $(CONNECTD_SRC) $(WEBSOCKETD_HEADERS) $(WEBSOCKETD_SRC)

check-units: $(CONNECTD_TEST_PROGRAMS:%=unittest/%)

