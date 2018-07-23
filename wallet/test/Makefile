WALLET_TEST_SRC := $(wildcard wallet/test/run-*.c)
WALLET_TEST_OBJS := $(WALLET_TEST_SRC:.c=.o)
WALLET_TEST_PROGRAMS := $(WALLET_TEST_OBJS:.o=)

WALLET_TEST_COMMON_OBJS :=			\
	common/base32.o				\
	common/derive_basepoints.o		\
	common/htlc_state.o			\
	common/type_to_string.o			\
	common/memleak.o			\
	common/key_derive.o			\
	common/pseudorand.o			\
	common/timeout.o			\
	common/utils.o				\
	common/wireaddr.o			\
	common/version.o			\
	wire/towire.o				\
	wire/fromwire.o

# Make sure these depend on everything.
ALL_TEST_PROGRAMS += $(WALLET_TEST_PROGRAMS)
ALL_OBJS += $(WALLET_LIB_OBJS) $(WALLET_TEST_OBJS)

$(WALLET_TEST_PROGRAMS): $(BITCOIN_OBJS) $(WALLET_TEST_COMMON_OBJS)
$(WALLET_TEST_OBJS): $(WALLET_LIB_HEADERS) $(WALLET_LIB_SRC)

wallet/tests: $(WALLET_TEST_PROGRAMS:%=unittest/%)

$(WALLET_TEST_PROGRAMS): $(WALLET_TEST_COMMON_OBJS) $(BITCOIN_OBJS)
$(WALLET_TEST_OBJS): $(WALLET_SRC)

update-mocks: $(WALLET_TEST_SRC:%=update-mocks/%)

check: $(WALLET_TEST_PROGRAMS:%=unittest/%)
