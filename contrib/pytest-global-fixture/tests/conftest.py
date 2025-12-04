import pytest
import psycopg2


@pytest.fixture(scope="function")
def postgres_db(global_resource):
    """
    User-facing fixture.
    1. Tells coordinator to load 'tests.resources:PostgresService'
    2. Coordinator starts Docker (if not running).
    3. Coordinator creates a dedicated DB for this test.
    4. Returns connection to that dedicated DB.
    """
    # Request the service by Class Path
    db_config = global_resource("tests.resources:PostgresService")

    # Create the actual connection object for the test to use
    conn = psycopg2.connect(**db_config)
    conn.autocommit = True

    yield conn

    conn.close()
    # After yield, 'global_resource' fixture automatically calls remove_tenant
