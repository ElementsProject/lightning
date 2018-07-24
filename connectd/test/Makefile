check: connectd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CONNECTD_TEST_SRC := $(wildcard connectd/test/run-*.c)
CONNECTD_TEST_OBJS := $(CONNECTD_TEST_SRC:.c=.o)
CONNECTD_TEST_PROGRAMS := $(CONNECTD_TEST_OBJS:.o=)

CONNECTD_TEST_COMMON_OBJS :=			\
	common/features.o			\
	common/pseudorand.o			\
	common/type_to_string.o			\
	common/utils.o

update-mocks: $(CONNECTD_TEST_SRC:%=update-mocks/%)

$(CONNECTD_TEST_PROGRAMS): $(CONNECTD_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(CONNECTD_TEST_OBJS): $(LIGHTNINGD_CONNECT_HEADERS) $(LIGHTNINGD_CONNECT_SRC)

ALL_OBJS += $(CONNECTD_TEST_OBJS)
ALL_TEST_PROGRAMS += $(CONNECTD_TEST_PROGRAMS)

connectd-tests: $(CONNECTD_TEST_PROGRAMS:%=unittest/%)

