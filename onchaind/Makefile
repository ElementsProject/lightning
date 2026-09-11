#! /usr/bin/make

ONCHAIND_HEADERS :=				\
	onchaind/onchaind_wiregen.h		\
	onchaind/onchain_types_names_gen.h	\
	onchaind/onchain_types.h		\
	onchaind/onchaind_wire.h

ONCHAIND_SRC := onchaind/onchaind.c	\
	onchaind/onchaind_wiregen.c	\
	onchaind/onchaind_wire.c

onchaind/onchain_types_names_gen.h: onchaind/onchain_types.h $(CDUMP_ENUMSTR)
	$(CDUMP_ENUMSTR) onchaind/onchain_types.h > $@

ONCHAIND_OBJS := $(ONCHAIND_SRC:%.c=$(BUILDDIR)/%.o)
$(ONCHAIND_OBJS): $(ONCHAIND_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(ONCHAIND_SRC)
ALL_C_HEADERS += $(ONCHAIND_HEADERS)
ALL_PROGRAMS += $(BUILDDIR)/lightningd/lightning_onchaind

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += \
	onchaind/onchaind_wiregen.h \
	onchaind/onchaind_wire.h
LIGHTNINGD_CONTROL_OBJS += \
	$(addprefix $(BUILDDIR)/, \
	onchaind/onchaind_wiregen.o \
	onchaind/onchaind_wire.o \
	)

$(BUILDDIR)/lightningd/lightning_onchaind: $(ONCHAIND_OBJS) $(HSMD_CLIENT_OBJS) $(BUILDDIR)/libcommon.a

obsclean::
	$(RM) onchaind/*.o

include onchaind/test/Makefile
