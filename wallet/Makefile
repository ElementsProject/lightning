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

WALLET_LIB_OBJS := $(WALLET_LIB_SRC:.c=.o) wallet/db_sqlite3.o
WALLET_LIB_HEADERS := $(WALLET_LIB_SRC:.c=.h)

# Make sure these depend on everything.
ALL_OBJS += $(WALLET_LIB_OBJS)

$(WALLET_LIB_OBJS): $(LIGHTNINGD_HEADERS_NOGEN) $(WALLET_LIB_HEADERS)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)
check-source: $(WALLET_LIB_SRC:%=check-src-include-order/%)
check-source: $(WALLET_LIB_HEADERS:%=check-hdr-include-order/%)
check-source-bolt: $(WALLET_LIB_SRC:%=bolt-check/%) $(WALLET_LIB_HEADERS:%=bolt-check/%)

clean: wallet-clean

wallet/db_sqlite3.c: wallet/gen_db_sqlite3.c

wallet/gen_db_sqlite3.c: devtools/sql-rewrite.py wallet/db.c wallet/wallet.c wallet/test/run-db.c
	LD_LIBRARY_PATH=${LIBCLANG_PATH} devtools/sql-rewrite.py -f sqlite3 > wallet/gen_db_sqlite3.c

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)

include wallet/test/Makefile
