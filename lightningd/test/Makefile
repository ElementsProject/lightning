check: lightningd/tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

update-mocks: $(LIGHTNINGD_TEST_SRC:%=update-mocks/%)

$(LIGHTNINGD_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS) $(LIBBASE58_OBJS) libsecp256k1.a utils.o $(LIGHTNINGD_HANDSHAKE_GEN_SRC:.c=.o)

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(WIRE_HEADERS) $(CCAN_HEADERS) $(LIBBASE58_HEADERS)

lightningd/tests: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)

