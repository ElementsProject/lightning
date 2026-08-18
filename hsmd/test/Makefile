check-units: hsmd-tests

# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
HSMD_TEST_SRC := $(wildcard hsmd/test/run-*.c)
HSMD_TEST_OBJS := $(HSMD_TEST_SRC:.c=.o)
HSMD_TEST_PROGRAMS := $(HSMD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(HSMD_TEST_SRC)
ALL_TEST_PROGRAMS += $(HSMD_TEST_PROGRAMS)

# hsmd.c is #included by the tests (so we can see statics).  Do not also
# link hsmd.o, or we get duplicate symbols.  libhsmd.o still supplies the
# request handlers.
$(HSMD_TEST_PROGRAMS): libcommon.a hsmd/libhsmd.o hsmd/hsm_utxo.o hsmd/hsmd_wiregen.o

$(HSMD_TEST_OBJS): $(HSMD_HEADERS) $(HSMD_SRC) hsmd/test/Makefile

hsmd-tests: $(HSMD_TEST_PROGRAMS:%=unittest/%)
