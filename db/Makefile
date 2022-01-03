#! /usr/bin/make

DB_LIB_SRC := 			\
	db/bindings.c		\
	db/exec.c		\
	db/utils.c

DB_DRIVERS :=			\
	db/db_postgres.c	\
	db/db_sqlite3.c

DB_SRC := $(DB_LIB_SRC) $(DB_DRIVERS)
DB_HEADERS := $(DB_LIB_SRC:.c=.h) db/common.h

DB_OBJS := $(DB_LIB_SRC:.c=.o) $(DB_DRIVERS:.c=.o)
$(DB_OBJS): $(DB_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(DB_SRC)
ALL_C_HEADERS += $(DB_HEADERS)

# DB_SQL_FILES is the list of database files
DB_SQL_FILES := db/exec.c
