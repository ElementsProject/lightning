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

WALLET_SRC := $(WALLET_LIB_SRC) $(WALLET_LIB_SRC_NOHDR) $(WALLET_DB_DRIVERS)
WALLET_HDRS := $(WALLET_LIB_SRC:.c=.h)

WALLET_OBJS := $(WALLET_SRC:.c=.o)
$(WALLET_OBJS): $(WALLET_HDRS) $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(WALLET_SRC)
ALL_C_HEADERS += $(WALLET_HDRS)

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

clean: wallet_clean
wallet-clean:
	$(RM) wallet/statements.po
	$(RM) wallet/gen_db_sqlite3.c
	$(RM) wallet/gen_db_postgres.c

include wallet/test/Makefile
