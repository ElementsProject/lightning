check: wire-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
WIRE_TEST_SRC := $(wildcard wire/test/run-*.c)
WIRE_TEST_OBJS := $(WIRE_TEST_SRC:.c=.o)
WIRE_TEST_PROGRAMS := $(WIRE_TEST_OBJS:.o=)

WIRE_TEST_COMMON_OBJS :=		\
	common/utils.o

update-mocks: $(WIRE_TEST_SRC:%=update-mocks/%)

$(WIRE_TEST_PROGRAMS): $(WIRE_TEST_COMMON_OBJS) $(BITCOIN_OBJS)

# Test objects require source to be generated, since they include ..
$(WIRE_TEST_OBJS): $(WIRE_GEN_SRC) $(WIRE_SRC) $(WIRE_HEADERS)

ALL_OBJS += $(WIRE_TEST_OBJS)
ALL_TEST_PROGRAMS += $(WIRE_TEST_PROGRAMS)

wire-tests: $(WIRE_TEST_PROGRAMS:%=unittest/%)

