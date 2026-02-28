PLUGIN_ASKRENE_SRC := \
	plugins/askrene/askrene.c \
	plugins/askrene/datastore_wire.c \
	plugins/askrene/layer.c \
	plugins/askrene/reserve.c \
	plugins/askrene/mcf.c \
	plugins/askrene/dijkstra.c \
	plugins/askrene/flow.c \
	plugins/askrene/refine.c \
	plugins/askrene/explain_failure.c \
	plugins/askrene/graph.c \
	plugins/askrene/priorityqueue.c \
	plugins/askrene/algorithm.c

PLUGIN_ASKRENE_HEADER := \
	plugins/askrene/askrene.h \
	plugins/askrene/datastore_wire.h \
	plugins/askrene/layer.h \
	plugins/askrene/reserve.h \
	plugins/askrene/mcf.h \
	plugins/askrene/dijkstra.h \
	plugins/askrene/flow.h \
	plugins/askrene/refine.h \
	plugins/askrene/explain_failure.h \
	plugins/askrene/graph.h \
	plugins/askrene/priorityqueue.h \
	plugins/askrene/algorithm.h

PLUGIN_ASKRENE_OBJS := $(PLUGIN_ASKRENE_SRC:.c=.o)

$(PLUGIN_ASKRENE_OBJS): $(PLUGIN_ASKRENE_HEADER) plugins/askrene/Makefile

PLUGIN_ALL_SRC += $(PLUGIN_ASKRENE_SRC)
PLUGIN_ALL_HEADER += $(PLUGIN_ASKRENE_HEADER)

plugins/cln-askrene: $(PLUGIN_ASKRENE_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

include plugins/askrene/test/Makefile
