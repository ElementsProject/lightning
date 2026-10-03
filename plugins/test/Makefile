# Note that these actually #include everything they need, except ccan/, bitcoin/ and wire/
# That allows for unit testing of statics, and special effects.
PLUGIN_TEST_SRC := $(wildcard plugins/test/run-*.c)
PLUGIN_TEST_OBJS := $(PLUGIN_TEST_SRC:%.c=$(BUILDDIR)/%.o)
PLUGIN_TEST_PROGRAMS := $(PLUGIN_TEST_OBJS:.o=)

ALL_C_SOURCES += $(PLUGIN_TEST_SRC)
ALL_TEST_PROGRAMS += $(PLUGIN_TEST_PROGRAMS)

$(BUILDDIR)/plugins/test/run-route-overlong:	\
	$(addprefix $(BUILDDIR)/,		\
	plugins/channel_hint.o			\
	)

$(BUILDDIR)/plugins/test/run-route-calc:	\
	$(addprefix $(BUILDDIR)/,		\
	common/fp16.o				\
	common/gossmap.o			\
	common/node_id.o			\
	common/route.o				\
	plugins/channel_hint.o			\
	)

$(PLUGIN_TEST_PROGRAMS): $(BUILDDIR)/libcommon.a

$(PLUGIN_TEST_OBJS): $(PLUGIN_ALL_HEADER) $(PLUGIN_ALL_SRC) plugins/test/Makefile

check-units: $(PLUGIN_TEST_PROGRAMS:%=unittest/%)

obsclean::
	$(RM) plugins/test/*.o
