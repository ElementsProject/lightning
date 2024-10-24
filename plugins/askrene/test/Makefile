# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
PLUGIN_ASKRENE_TEST_SRC := $(wildcard plugins/askrene/test/run-*.c)
PLUGIN_ASKRENE_TEST_OBJS := $(PLUGIN_ASKRENE_TEST_SRC:.c=.o)
PLUGIN_ASKRENE_TEST_PROGRAMS := $(PLUGIN_ASKRENE_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_ASKRENE_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_ASKRENE_TEST_PROGRAMS)
$(PLUGIN_RENEPAY_TEST_OBJS): $(PLUGIN_ASKRENE_SRC)

PLUGIN_ASKRENE_TEST_COMMON_OBJS :=

plugins/askrene/test/run-bfs plugins/askrene/test/run-dijkstra plugins/askrene/test/run-flow plugins/askrene/test/run-mcf plugins/askrene/test/run-mcf-large: \
	plugins/askrene/priorityqueue.o \
	plugins/askrene/graph.o

$(PLUGIN_ASKRENE_TEST_PROGRAMS): $(PLUGIN_ASKRENE_TEST_COMMON_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS)

check-askrene: $(PLUGIN_ASKRENE_TEST_PROGRAMS:%=unittest/%)

check-units: check-askrene

