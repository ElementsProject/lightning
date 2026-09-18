check-units: wire-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
WIRE_TEST_SRC := $(wildcard wire/test/run-*.c)
WIRE_TEST_OBJS := $(WIRE_TEST_SRC:%.c=$(BUILDDIR)/%.o)
WIRE_TEST_PROGRAMS := $(WIRE_TEST_OBJS:.o=)

ALL_C_SOURCES += $(WIRE_TEST_SRC)
ALL_TEST_PROGRAMS += $(WIRE_TEST_PROGRAMS)

WIRE_TEST_COMMON_OBJS :=		\
	$(addprefix $(BUILDDIR)/,	\
	common/autodata.o		\
	common/base32.o			\
	common/pseudorand.o		\
	common/setup.o			\
	common/utils.o			\
	common/wireaddr.o		\
	)

# run-tlvstream.c and run-peer-wire.c provide their own mocks for randbytes_ and randbytes_overridden
# run-tlvstream.c needs to reach into bitcoin/pubkey for SUPERVERBOSE
$(WIRE_TEST_PROGRAMS): $(WIRE_TEST_COMMON_OBJS) $(filter-out $(addprefix $(BUILDDIR)/bitcoin/,pubkey.o chainparams.o),$(BITCOIN_OBJS))

$(WIRE_TEST_OBJS): $(WIRE_HEADERS) $(WIRE_SRC) $(WIRE_PRINT_SRC) wire/test/Makefile

wire-tests: $(WIRE_TEST_PROGRAMS:%=unittest/%)

$(BUILDDIR)/wire/test/run-peer-wire: $(addprefix $(BUILDDIR)/,wire/peer_wiregen.o common/bigsize.o)

obsclean::
	$(RM) wire/test/*.o
