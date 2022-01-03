#include "config.h"
#include "db_sqlite3_sqlgen.c"

#if HAVE_SQLITE3
struct db_query_set sqlite3_query_set = {
	.name = "sqlite3",
	.query_table = db_sqlite3_queries,
	.query_table_size = ARRAY_SIZE(db_sqlite3_queries),
};

AUTODATA(db_queries, &sqlite3_query_set);
#endif /* HAVE_SQLITE3 */
