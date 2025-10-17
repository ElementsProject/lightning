check-units: onchaind-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
ONCHAIND_TEST_SRC := $(wildcard onchaind/test/run-*.c)
ONCHAIND_TEST_OBJS := $(ONCHAIND_TEST_SRC:.c=.o)
ONCHAIND_TEST_PROGRAMS := $(ONCHAIND_TEST_OBJS:.o=)

ALL_C_SOURCES += $(ONCHAIND_TEST_SRC)
ALL_TEST_PROGRAMS += $(ONCHAIND_TEST_PROGRAMS)

# test/run-grind_feerate-bug uses its own htlc_timeout_tx()
$(filter-out onchaind/test/run-grind_feerate-bug,$(ONCHAIND_TEST_PROGRAMS)): libcommon.a

onchaind/test/run-grind_feerate-bug:		\
	$(BITCOIN_OBJS)				\
	wire/towire.o				\
	wire/fromwire.o				\
	common/amount.o				\
	common/autodata.o			\
	common/features.o			\
	common/psbt_keypath.o			\
	common/pseudorand.o			\
	common/setup.o				\
	common/utils.o

# Test objects depend on ../ src and headers.
$(ONCHAIND_TEST_OBJS): $(ONCHAIND_HEADERS) $(ONCHAIND_SRC) onchaind/test/Makefile

onchaind-tests: $(ONCHAIND_TEST_PROGRAMS:%=unittest/%)

