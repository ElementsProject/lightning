# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
LIGHTNINGD_TEST_SRC := $(wildcard lightningd/test/run-*.c)
LIGHTNINGD_TEST_OBJS := $(LIGHTNINGD_TEST_SRC:.c=.o)
LIGHTNINGD_TEST_PROGRAMS := $(LIGHTNINGD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(LIGHTNINGD_TEST_SRC)
ALL_TEST_PROGRAMS += $(LIGHTNINGD_TEST_PROGRAMS)

# run-find_my_abspath.c includes lightningd.c, which includes header_versions_gen.h
lightningd/test/run-find_my_abspath.o: header_versions_gen.h

$(LIGHTNINGD_TEST_PROGRAMS): libcommon.a

$(LIGHTNINGD_TEST_OBJS): $(LIGHTNINGD_HDRS) $(LIGHTNINGD_SRC) $(LIGHTNINGD_SRC_NOHDR) lightningd/test/Makefile

check-units: $(LIGHTNINGD_TEST_PROGRAMS:%=unittest/%)
