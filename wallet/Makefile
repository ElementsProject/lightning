#! /usr/bin/make

# Designed to be run one level up
wallet-wrongdir:
	$(MAKE) -C .. lightningd-all

WALLET_LIB_SRC :=		\
	wallet/db.c		\
	wallet/invoices.c	\
	wallet/wallet.c		\
	wallet/walletrpc.c

WALLET_LIB_OBJS := $(WALLET_LIB_SRC:.c=.o)
WALLET_LIB_HEADERS := $(WALLET_LIB_SRC:.c=.h)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)

clean: wallet-clean

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)

include wallet/test/Makefile
