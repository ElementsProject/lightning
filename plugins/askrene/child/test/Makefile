# Note that these actually #include everything they need, except ccan/ and bitcoin/.
# That allows for unit testing of statics, and special effects.
ASKRENE_TEST_PREFIX := plugins/askrene/child/test
PLUGIN_ASKRENE_TEST_SRC := $(wildcard $(ASKRENE_TEST_PREFIX)/run-*.c)
PLUGIN_ASKRENE_TEST_OBJS := $(PLUGIN_ASKRENE_TEST_SRC:.c=.o)
PLUGIN_ASKRENE_TEST_PROGRAMS := $(PLUGIN_ASKRENE_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_ASKRENE_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_ASKRENE_TEST_PROGRAMS)
$(PLUGIN_ASKRENE_TEST_OBJS): $(PLUGIN_ASKRENE_SRC) $(ASKRENE_TEST_PREFIX)/Makefile

$(ASKRENE_TEST_PREFIX)/run-bfs $(ASKRENE_TEST_PREFIX)/run-dijkstra $(ASKRENE_TEST_PREFIX)/run-flow $(ASKRENE_TEST_PREFIX)/run-mcf $(ASKRENE_TEST_PREFIX)/run-mcf-large: \
	plugins/askrene/child/priorityqueue.o \
	plugins/askrene/child/graph.o

$(PLUGIN_ASKRENE_TEST_PROGRAMS): $(PLUGIN_LIB_OBJS) libcommon.a

check-askrene: $(PLUGIN_ASKRENE_TEST_PROGRAMS:%=unittest/%)

check-units: check-askrene
