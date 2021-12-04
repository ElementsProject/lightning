check-units: onchaind-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
ONCHAIND_TEST_SRC := $(wildcard onchaind/test/run-*.c)
ONCHAIND_TEST_OBJS := $(ONCHAIND_TEST_SRC:.c=.o)
ONCHAIND_TEST_PROGRAMS := $(ONCHAIND_TEST_OBJS:.o=)

ALL_C_SOURCES += $(ONCHAIND_TEST_SRC)
ALL_TEST_PROGRAMS += $(ONCHAIND_TEST_PROGRAMS)

ONCHAIND_TEST_COMMON_OBJS :=			\
	common/amount.o				\
	common/autodata.o			\
	common/features.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/type_to_string.o			\
	common/utils.o

$(ONCHAIND_TEST_PROGRAMS): $(ONCHAIND_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# This needs many more objs:
onchaind/test/run-onchainstress:		\
	common/htlc_tx.o			\
	common/derive_basepoints.o		\
	common/daemon.o				\
	common/htlc_wire.o			\
	common/initial_commit_tx.o		\
	common/key_derive.o			\
	common/keyset.o				\
	common/permute_tx.o			\
	common/subdaemon.o			\
	common/wallet.o				\
	wire/towire.o				\
	wire/fromwire.o

# Test objects depend on ../ src and headers.
$(ONCHAIND_TEST_OBJS): $(ONCHAIND_HEADERS) $(ONCHAIND_SRC)

onchaind-tests: $(ONCHAIND_TEST_PROGRAMS:%=unittest/%)

