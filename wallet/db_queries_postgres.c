#include "config.h"
#include "db_postgres_sqlgen.c"

#if HAVE_POSTGRES

struct db_query_set postgres_query_set = {
	.name = "postgres",
	.query_table = db_postgres_queries,
	.query_table_size = ARRAY_SIZE(db_postgres_queries),
};

AUTODATA(db_queries, &postgres_query_set);
#endif /* HAVE_POSTGRES */
