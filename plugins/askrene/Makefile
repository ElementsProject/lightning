PLUGIN_ASKRENE_PARENT_SRC := \
	plugins/askrene/askrene.c \
	plugins/askrene/datastore_wire.c \
	plugins/askrene/layer.c \
	plugins/askrene/reserve.c \

PLUGIN_ASKRENE_CHILD_SRC := \
	plugins/askrene/child/entry.c \
	plugins/askrene/child/mcf.c \
	plugins/askrene/child/dijkstra.c \
	plugins/askrene/child/flow.c \
	plugins/askrene/child/refine.c \
	plugins/askrene/child/explain_failure.c \
	plugins/askrene/child/graph.c \
	plugins/askrene/child/priorityqueue.c \
	plugins/askrene/child/algorithm.c \
	plugins/askrene/child/child_log.c \

PLUGIN_ASKRENE_SRC := $(PLUGIN_ASKRENE_PARENT_SRC) $(PLUGIN_ASKRENE_CHILD_SRC)
PLUGIN_ASKRENE_HEADER := $(PLUGIN_ASKRENE_SRC:.c=.h)

PLUGIN_ASKRENE_OBJS := $(PLUGIN_ASKRENE_SRC:.c=.o)

$(PLUGIN_ASKRENE_OBJS): $(PLUGIN_ASKRENE_HEADER) plugins/askrene/Makefile

PLUGIN_ALL_SRC += $(PLUGIN_ASKRENE_SRC)
PLUGIN_ALL_HEADER += $(PLUGIN_ASKRENE_HEADER)

plugins/cln-askrene: $(PLUGIN_ASKRENE_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

include plugins/askrene/test/Makefile
