check-units: wire-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
WIRE_TEST_SRC := $(wildcard wire/test/run-*.c)
WIRE_TEST_OBJS := $(WIRE_TEST_SRC:.c=.o)
WIRE_TEST_PROGRAMS := $(WIRE_TEST_OBJS:.o=)

ALL_C_SOURCES += $(WIRE_TEST_SRC)
ALL_TEST_PROGRAMS += $(WIRE_TEST_PROGRAMS)

WIRE_TEST_COMMON_OBJS :=		\
	common/autodata.o		\
	common/base32.o			\
	common/pseudorand.o		\
	common/setup.o			\
	common/utils.o			\
	common/wireaddr.o

# run-tlvstream.c needs to reach into bitcoin/pubkey for SUPERVERBOSE
$(WIRE_TEST_PROGRAMS): $(WIRE_TEST_COMMON_OBJS) $(filter-out bitcoin/pubkey.o bitcoin/chainparams.o,$(BITCOIN_OBJS))

# We put a dependency on non-exp sources here, so they get built even if
# we're EXPERIMENTAL_FEATURES.
$(WIRE_TEST_OBJS): $(WIRE_HEADERS) $(WIRE_SRC) $(WIRE_PRINT_SRC) $(WIRE_NONEXP_SRC)

wire-tests: $(WIRE_TEST_PROGRAMS:%=unittest/%)

wire/test/run-peer-wire: wire/peer$(EXP)_wiregen.o common/bigsize.o
