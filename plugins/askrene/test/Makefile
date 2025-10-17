# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
PLUGIN_ASKRENE_TEST_SRC := $(wildcard plugins/askrene/test/run-*.c)
PLUGIN_ASKRENE_TEST_OBJS := $(PLUGIN_ASKRENE_TEST_SRC:.c=.o)
PLUGIN_ASKRENE_TEST_PROGRAMS := $(PLUGIN_ASKRENE_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_ASKRENE_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_ASKRENE_TEST_PROGRAMS)
$(PLUGIN_RENEPAY_TEST_OBJS): $(PLUGIN_ASKRENE_SRC) plugins/askrene/test/Makefile

plugins/askrene/test/run-bfs plugins/askrene/test/run-dijkstra plugins/askrene/test/run-flow plugins/askrene/test/run-mcf plugins/askrene/test/run-mcf-large: \
	plugins/askrene/priorityqueue.o \
	plugins/askrene/graph.o

$(PLUGIN_ASKRENE_TEST_PROGRAMS): $(PLUGIN_LIB_OBJS) libcommon.a

check-askrene: $(PLUGIN_ASKRENE_TEST_PROGRAMS:%=unittest/%)

check-units: check-askrene

