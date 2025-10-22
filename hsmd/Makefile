#! /usr/bin/make

HSMD_SRC := hsmd/hsmd.c	\
	hsmd/hsmd_wiregen.c \
	hsmd/hsm_utxo.c \
	hsmd/libhsmd.c

HSMD_HEADERS := hsmd/hsmd_wiregen.h hsmd/permissions.h
HSMD_OBJS := $(HSMD_SRC:.c=.o)

$(HSMD_OBJS): $(HSMD_HEADERS)

# Other programs which use the hsm need this.
HSMD_CLIENT_OBJS := \
	hsmd/hsmd_wiregen.o			\
	hsmd/hsm_utxo.o				\

# Make sure these depend on everything.
ALL_C_SOURCES += $(HSMD_SRC)
ALL_C_HEADERS += $(HSMD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_hsmd

lightningd/lightning_hsmd: $(HSMD_OBJS) libcommon.a

check-source: check-hsm-versions

# common/hsm_version.h should at least *mention* this!
check-hsm-versions: hsmd/hsmd_wire.csv common/hsm_version.h
	@SUM=`grep -vE '^(#| *$$)' hsmd/hsmd_wire.csv  | sha256sum | cut -c1-64`; if ! grep -q "$$SUM" common/hsm_version.h; then echo "*** hsmd_wire.csv changed to $$SUM without update to common/hsm_version.h">&2; exit 1; fi

-include hsmd/test/Makefile
