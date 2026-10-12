# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
OPENINGD_TEST_SRC := $(wildcard openingd/test/run-*.c)
OPENINGD_TEST_OBJS := $(OPENINGD_TEST_SRC:.c=.o)
OPENINGD_TEST_PROGRAMS := $(OPENINGD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(OPENINGD_TEST_SRC)
ALL_TEST_PROGRAMS += $(OPENINGD_TEST_PROGRAMS)

$(OPENINGD_TEST_PROGRAMS): libcommon.a

$(OPENINGD_TEST_OBJS): $(OPENINGD_HEADERS) $(OPENINGD_SRC) openingd/test/Makefile

check-units: $(OPENINGD_TEST_PROGRAMS:%=unittest/%)
