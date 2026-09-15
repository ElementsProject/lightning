#! /usr/bin/make

CHANNELD_HEADERS :=			\
	channeld/full_channel_error_names_gen.h	\
	channeld/channeld_wiregen.h		\
	channeld/channeld_htlc.h		\
	channeld/channeld.h			\
	channeld/commit_tx.h			\
	channeld/full_channel.h			\
	channeld/full_channel_error.h		\
	channeld/watchtower.h

CHANNELD_SRC := channeld/channeld.c	\
	channeld/commit_tx.c			\
	channeld/full_channel.c			\
	channeld/splice.c			\
	channeld/inflight.c			\
	channeld/channeld_wiregen.c		\
	channeld/watchtower.c

CHANNELD_OBJS := $(CHANNELD_SRC:%.c=$(BUILDDIR)/%.o)
$(CHANNELD_OBJS): $(CHANNELD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CHANNELD_SRC)
ALL_C_HEADERS += $(CHANNELD_HEADERS)
ALL_PROGRAMS += $(BUILDDIR)/lightningd/lightning_channeld

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += \
	channeld/channeld_wiregen.h \
	channeld/inflight.h
LIGHTNINGD_CONTROL_OBJS += \
	$(addprefix $(BUILDDIR)/, \
	channeld/channeld_wiregen.o \
	channeld/inflight.o \
	)

channeld/full_channel_error_names_gen.h: channeld/full_channel_error.h $(CDUMP_ENUMSTR)
	$(CDUMP_ENUMSTR) channeld/full_channel_error.h > $@

$(BUILDDIR)/lightningd/lightning_channeld: $(CHANNELD_OBJS) $(HSMD_CLIENT_OBJS) $(BUILDDIR)/libcommon.a

obsclean::
	$(RM) channeld/*.o

include channeld/test/Makefile
