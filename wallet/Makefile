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

WALLET_LIB_SRC_NOHDR :=		\
	wallet/reservation.c

WALLET_DB_DRIVERS :=		\
	wallet/db_postgres.c	\
	wallet/db_sqlite3.c

WALLET_LIB_OBJS := $(WALLET_LIB_SRC:.c=.o) $(WALLET_LIB_SRC_NOHDR:.c=.o) $(WALLET_DB_DRIVERS:.c=.o)
WALLET_LIB_HEADERS := $(WALLET_LIB_SRC:.c=.h)

# Make sure these depend on everything.
ALL_OBJS += $(WALLET_LIB_OBJS)

$(WALLET_LIB_OBJS): $(LIGHTNINGD_HEADERS_NOGEN) $(WALLET_LIB_HEADERS)

check-whitespace: $(WALLET_LIB_SRC:%=check-whitespace/%) $(WALLET_LIB_HEADERS:%=check-whitespace/%)
check-source: $(WALLET_LIB_SRC:%=check-src-include-order/%)
check-source: $(WALLET_LIB_HEADERS:%=check-hdr-include-order/%)
check-source-bolt: $(WALLET_LIB_SRC:%=bolt-check/%) $(WALLET_LIB_HEADERS:%=bolt-check/%)

clean: wallet-clean

# Each database driver depends on its rewritten statements.
wallet/db_sqlite3.o: wallet/gen_db_sqlite3.c
wallet/db_postgres.o: wallet/gen_db_postgres.c

# The following files contain SQL-annotated statements that we need to extact
SQL_FILES := 				\
	wallet/db.c 			\
	wallet/invoices.c		\
	wallet/wallet.c 		\
	wallet/test/run-db.c		\
	wallet/test/run-wallet.c	\

wallet/statements.po: $(SQL_FILES)
	xgettext -kNAMED_SQL -kSQL --add-location --no-wrap --omit-header -o $@ $(SQL_FILES)

wallet/gen_db_%.c:  wallet/statements.po devtools/sql-rewrite.py
	devtools/sql-rewrite.py wallet/statements.po $* > wallet/gen_db_$*.c

wallet-clean:
	$(RM) $(WALLET_LIB_OBJS)
	$(RM) wallet/statements.po
	$(RM) wallet/gen_db_sqlite3.c
	$(RM) wallet/gen_db_postgres.c

include wallet/test/Makefile
