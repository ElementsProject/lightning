check: wire-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
WIRE_TEST_SRC := $(wildcard wire/test/run-*.c)
WIRE_TEST_OBJS := $(WIRE_TEST_SRC:.c=.o)
WIRE_TEST_PROGRAMS := $(WIRE_TEST_OBJS:.o=)

update-mocks: $(WIRE_TEST_SRC:%=update-mocks/%)

$(WIRE_TEST_PROGRAMS): $(CCAN_OBJS) $(BITCOIN_OBJS) libsecp256k1.a utils.o

$(WIRE_TEST_OBJS): $(WIRE_HEADERS) $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS) $(WIRE_GEN_HEADERS) $(WIRE_GEN_SRC) $(CCAN_HEADERS)

wire-tests: $(WIRE_TEST_PROGRAMS:%=unittest/%)

