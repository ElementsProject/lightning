#! /usr/bin/make

# Designed to be run one level up
wallet-wrongdir:
	$(MAKE) -C .. lightningd-all

WALLET_LIB_SRC :=		\
	wallet/db.c		\
	wallet/invoices.c	\
	wallet/txfilter.c	\
	wallet/wallet.c		\
	wallet/walletrpc.c

WALLET_LIB_OBJS := $(WALLET_LIB_SRC:.c=.o)
WALLET_LIB_HEADERS := $(WALLET_LIB_SRC:.c=.h)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_OBJS)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)
check-source: $(WALLET_LIB_SRC:%=check-src-include-order/%)
check-source: $(WALLET_LIB_HEADERS:%=check-hdr-include-order/%)
check-source-bolt: $(WALLET_LIB_SRC:%=bolt-check/%) $(WALLET_LIB_HEADERS:%=bolt-check/%)

clean: wallet-clean

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)

include wallet/test/Makefile
