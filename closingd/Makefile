#! /usr/bin/make

CLOSINGD_HEADERS := closingd/closingd_wiregen.h

CLOSINGD_SRC := closingd/closingd.c	\
	$(CLOSINGD_HEADERS:.h=.c)

CLOSINGD_OBJS := $(CLOSINGD_SRC:.c=.o)
$(CLOSINGD_OBJS): $(CLOSINGD_HEADERS)

# Simple close daemon
SIMPLECLOSED_HEADERS := closingd/simpleclosed_wiregen.h

SIMPLECLOSED_SRC := closingd/simpleclosed.c	\
	$(SIMPLECLOSED_HEADERS:.h=.c)

SIMPLECLOSED_OBJS := $(SIMPLECLOSED_SRC:.c=.o)
$(SIMPLECLOSED_OBJS): $(SIMPLECLOSED_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(CLOSINGD_SRC) $(SIMPLECLOSED_SRC)
ALL_C_HEADERS += $(CLOSINGD_HEADERS) $(SIMPLECLOSED_HEADERS)
ALL_PROGRAMS += lightningd/lightning_closingd lightningd/lightning_simpleclosed

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += closingd/closingd_wiregen.h closingd/simpleclosed_wiregen.h
LIGHTNINGD_CONTROL_OBJS += closingd/closingd_wiregen.o closingd/simpleclosed_wiregen.o

lightningd/lightning_closingd: $(CLOSINGD_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

lightningd/lightning_simpleclosed: $(SIMPLECLOSED_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

-include closingd/test/Makefile
