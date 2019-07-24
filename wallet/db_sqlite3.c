#include <wallet/db_common.h>
#include "gen_db_sqlite3.c"
#if HAVE_SQLITE3

struct db_config db_sqlite3_config = {
	.name = "sqlite3",
	.queries = db_sqlite3_queries,
	.num_queries = DB_SQLITE3_QUERY_COUNT,
};

AUTODATA(db_backends, &db_sqlite3_config);

#endif
