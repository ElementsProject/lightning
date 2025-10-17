#! /usr/bin/make

OPENINGD_HEADERS := 				\
	openingd/common.h			\
	openingd/openingd_wiregen.h

DUALOPEND_HEADERS := 				\
	openingd/common.h			\
	openingd/dualopend_wiregen.h

OPENINGD_SRC := openingd/openingd.c		\
	$(OPENINGD_HEADERS:.h=.c)

DUALOPEND_SRC := openingd/dualopend.c		\
	$(DUALOPEND_HEADERS:.h=.c)

OPENINGD_OBJS := $(OPENINGD_SRC:.c=.o)
$(OPENINGD_OBJS): $(OPENINGD_HEADERS)

DUALOPEND_OBJS := $(DUALOPEND_SRC:.c=.o)
$(DUALOPEND_OBJS): $(DUALOPEND_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(OPENINGD_SRC) $(DUALOPEND_SRC)
ALL_C_HEADERS += $(OPENINGD_HEADERS) $(DUALOPEND_HEADERS)
ALL_PROGRAMS += lightningd/lightning_openingd lightningd/lightning_dualopend

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += openingd/openingd_wiregen.h openingd/dualopend_wiregen.h
LIGHTNINGD_CONTROL_OBJS += openingd/openingd_wiregen.o openingd/dualopend_wiregen.o

lightningd/lightning_openingd: $(OPENINGD_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

lightningd/lightning_dualopend: $(DUALOPEND_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

-include openingd/test/Makefile
