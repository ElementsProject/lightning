CLOSINGD_TEST_SRC := $(wildcard closingd/test/run-*.c)
CLOSINGD_TEST_OBJS := $(CLOSINGD_TEST_SRC:.c=.o)
CLOSINGD_TEST_PROGRAMS := $(CLOSINGD_TEST_OBJS:.o=)

ALL_C_SOURCES += $(CLOSINGD_TEST_SRC)
ALL_TEST_PROGRAMS += $(CLOSINGD_TEST_PROGRAMS)

$(CLOSINGD_TEST_PROGRAMS): libcommon.a
$(CLOSINGD_TEST_OBJS): $(CLOSINGD_SRC) $(CLOSINGD_HEADERS)

closingd/test/run-closingd-negotiation: closingd/closingd_wiregen.o

check-units: $(CLOSINGD_TEST_PROGRAMS:%=unittest/%)
