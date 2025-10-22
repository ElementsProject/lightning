#! /usr/bin/make

CLOSINGD_HEADERS := closingd/closingd_wiregen.h

CLOSINGD_SRC := closingd/closingd.c	\
	$(CLOSINGD_HEADERS:.h=.c)

CLOSINGD_OBJS := $(CLOSINGD_SRC:.c=.o)
$(CLOSINGD_OBJS): $(CLOSINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CLOSINGD_SRC)
ALL_C_HEADERS += $(CLOSINGD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_closingd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += closingd/closingd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += closingd/closingd_wiregen.o

lightningd/lightning_closingd: $(CLOSINGD_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

-include closingd/test/Makefile
