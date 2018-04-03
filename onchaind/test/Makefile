check: onchaind-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
ONCHAIND_TEST_SRC := $(wildcard onchaind/test/run-*.c)
ONCHAIND_TEST_OBJS := $(ONCHAIND_TEST_SRC:.c=.o)
ONCHAIND_TEST_PROGRAMS := $(ONCHAIND_TEST_OBJS:.o=)

ONCHAIND_TEST_COMMON_OBJS :=			\
	common/features.o			\
	common/pseudorand.o			\
	common/type_to_string.o			\
	common/utils.o

update-mocks: $(ONCHAIND_TEST_SRC:%=update-mocks/%)

$(ONCHAIND_TEST_PROGRAMS): $(ONCHAIND_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects depend on ../ src and headers.
$(ONCHAIND_TEST_OBJS): $(LIGHTNINGD_ONCHAIN_HEADERS) $(LIGHTNINGD_ONCHAIN_SRC)

ALL_OBJS += $(ONCHAIND_TEST_OBJS)
ALL_TEST_PROGRAMS += $(ONCHAIND_TEST_PROGRAMS)

onchaind-tests: $(ONCHAIND_TEST_PROGRAMS:%=unittest/%)

