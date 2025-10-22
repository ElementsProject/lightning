check-units: gossipd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
GOSSIPD_TEST_SRC := $(wildcard gossipd/test/run-*.c)
GOSSIPD_TEST_OBJS := $(GOSSIPD_TEST_SRC:.c=.o)
GOSSIPD_TEST_PROGRAMS := $(GOSSIPD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(GOSSIPD_TEST_SRC)
ALL_TEST_PROGRAMS += $(GOSSIPD_TEST_PROGRAMS)

$(GOSSIPD_TEST_PROGRAMS): libcommon.a

# Test objects depend on ../ src and headers.
$(GOSSIPD_TEST_OBJS): $(GOSSIPD_HEADERS) $(GOSSIPD_SRC) gossipd/test/Makefile

gossipd-tests: $(GOSSIPD_TEST_PROGRAMS:%=unittest/%)
