from pyln.testing.db import PostgresDbProvider


# Longest test name in the CLN test suite at the time of writing, at 66
# characters it exceeds what postgres can store in an identifier.
LONG_TESTNAME = "test_hsmtool_checkhsm_legacy_encrypted_with_mnemonic_no_passphrase"

# Hardcoded rather than taken from PostgresDbProvider, so that changing
# the limit in the provider fails these tests instead of silencing them.
MAX_IDENTIFIER_LEN = 63


def test_long_testname_fits_postgres_identifier():
    name = PostgresDbProvider.db_name(LONG_TESTNAME, 1, "abcd1234")

    assert len(name) <= MAX_IDENTIFIER_LEN


def test_long_testname_keeps_node_id_and_nonce():
    name = PostgresDbProvider.db_name(LONG_TESTNAME, 7, "abcd1234")

    assert name.endswith("_7_abcd1234")


def test_long_testname_distinct_per_node_after_truncation():
    # Postgres silently truncates at 63 bytes, so names must already be
    # distinct at that length or nodes of the same test collide.
    names = {PostgresDbProvider.db_name(LONG_TESTNAME, i, "abcd1234")[:MAX_IDENTIFIER_LEN]
             for i in range(5)}

    assert len(names) == 5


def test_long_testname_distinct_per_nonce_after_truncation():
    n1 = PostgresDbProvider.db_name(LONG_TESTNAME, 1, "abcd1234")[:MAX_IDENTIFIER_LEN]
    n2 = PostgresDbProvider.db_name(LONG_TESTNAME, 1, "wxyz5678")[:MAX_IDENTIFIER_LEN]

    assert n1 != n2


def test_short_testname_is_not_truncated():
    name = PostgresDbProvider.db_name("test_peers", 1, "abcd1234")

    assert name == "test_peers_1_abcd1234"
