#include <wallet/db_common.h>
#include "gen_db_postgres.c"
#include <ccan/ccan/tal/str/str.h>
#include <lightningd/log.h>
#include <sqlite3.h>
#include <stdio.h>

#if HAVE_POSTGRES

struct db_config db_postgres_config = {
	.name = "postgres",
	.queries = NULL,
	.num_queries = DB_POSTGRES_QUERY_COUNT,
	.exec_fn = NULL,
	.query_fn = NULL,
	.step_fn = NULL,
	.begin_tx_fn = NULL,
	.commit_tx_fn = NULL,
	.stmt_free_fn = NULL,

	.column_is_null_fn = NULL,
	.column_u64_fn = NULL,
	.column_int_fn = NULL,
	.column_bytes_fn = NULL,
	.column_blob_fn = NULL,
	.column_text_fn = NULL,

	.last_insert_id_fn = NULL,
	.count_changes_fn = NULL,
	.setup_fn = NULL,
	.teardown_fn = NULL,
};

AUTODATA(db_backends, &db_postgres_config);

#endif
