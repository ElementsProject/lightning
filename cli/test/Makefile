# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
CLI_TEST_SRC := $(wildcard cli/test/run-*.c)
CLI_TEST_OBJS := $(CLI_TEST_SRC:.c=.o)
CLI_TEST_PROGRAMS := $(CLI_TEST_OBJS:.o=)

ALL_C_SOURCES += $(CLI_TEST_SRC)
ALL_TEST_PROGRAMS += $(CLI_TEST_PROGRAMS)

$(CLI_TEST_PROGRAMS): libcommon.a

$(CLI_TEST_OBJS): $(LIGHTNING_CLI_HEADERS) $(LIGHTNING_CLI_SRC) cli/test/Makefile

check-units: $(CLI_TEST_PROGRAMS:%=unittest/%)
