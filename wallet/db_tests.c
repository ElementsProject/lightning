#include "db.c"

#include "wallet/test_utils.h"

#include <stdio.h>
#include <unistd.h>

static struct db *create_test_db(const char *testname)
{
	struct db *db;
	char filename[] = "/tmp/ldb-XXXXXX";

	int fd = mkstemp(filename);
	if (fd == -1)
		return NULL;
	close(fd);

	db = db_open(NULL, filename);
	return db;
}

static bool test_empty_db_migrate(void)
{
	struct db *db = create_test_db(__func__);
	CHECK(db);
	db_begin_transaction(db);
	CHECK(db_get_version(db) == -1);
	db_commit_transaction(db);
	db_migrate(db);
	db_begin_transaction(db);
	CHECK(db_get_version(db) == db_migration_count());
	db_commit_transaction(db);

	tal_free(db);
	return true;
}

static bool test_primitives(void)
{
	struct db *db = create_test_db(__func__);
	db_begin_transaction(db);
	CHECK(db->in_transaction);
	db_commit_transaction(db);
	CHECK(!db->in_transaction);
	db_begin_transaction(db);
	db_commit_transaction(db);

	db_begin_transaction(db);
	CHECK_MSG(db_exec_mayfail(__func__, db, "SELECT name FROM sqlite_master WHERE type='table';"), "Simple correct SQL command");
	CHECK_MSG(!db_exec_mayfail(__func__, db, "not a valid SQL statement"), "Failing SQL command");
	db_commit_transaction(db);
	CHECK(!db->in_transaction);
	tal_free(db);

	return true;
}

static bool test_vars(void)
{
	struct db *db = create_test_db(__func__);
	char *varname = "testvar";
	CHECK(db);
	db_migrate(db);

	db_begin_transaction(db);
	/* Check default behavior */
	CHECK(db_get_intvar(db, varname, 42) == 42);

	/* Check setting and getting */
	db_set_intvar(db, varname, 1);
	CHECK(db_get_intvar(db, varname, 42) == 1);

	/* Check updating */
	db_set_intvar(db, varname, 2);
	CHECK(db_get_intvar(db, varname, 42) == 2);
	db_commit_transaction(db);

	tal_free(db);
	return true;
}

int main(void)
{
	bool ok = true;

	ok &= test_empty_db_migrate();
	ok &= test_vars();
	ok &= test_primitives();

	return !ok;
}
