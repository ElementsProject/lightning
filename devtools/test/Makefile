# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
DT_TEST_SRC := $(wildcard devtools/test/run-*.c)
DT_TEST_OBJS := $(DT_TEST_SRC:.c=.o)
DT_TEST_PROGRAMS := $(DT_TEST_OBJS:.o=)

ALL_C_SOURCES += $(DT_TEST_SRC)
ALL_C_HEADERS += 
ALL_TEST_PROGRAMS += $(DT_TEST_PROGRAMS)

$(DT_TEST_PROGRAMS): libccan.a $(BITCOIN_OBJS) $(WIRE_OBJS) $(DEVTOOLS_COMMON_OBJS)

$(DT_TEST_OBJS): $(LIGHTNING_DT_HEADERS) $(LIGHTNING_DT_SRC)

check-units: $(DT_TEST_PROGRAMS:%=unittest/%)
