check: lightningd/tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

update-mocks: $(LIGHTNINGD_TEST_SRC:%=update-mocks/%)

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(CCAN_SHACHAIN48_OBJ) $(CORE_OBJS) $(CORE_TX_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) $(LIGHTNINGD_OLD_LIB_OBJS) utils.o libsecp256k1.a libsodium.a libwallycore.a

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HEADERS) $(LIGHTNINGD_SRC) $(LIGHTNINGD_LIB_SRC)

lightningd/tests: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)

check-source-bolt: $(LIGHTNINGD_TEST_SRC:%=bolt-check/%)
check-whitespace: $(LIGHTNINGD_TEST_SRC:%=check-whitespace/%)
