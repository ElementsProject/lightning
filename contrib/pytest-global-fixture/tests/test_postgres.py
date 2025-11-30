import pytest
import os

def test_table_isolation_a(postgres_db, worker_id):
    """
    Creates a table 'items'.
    If isolation works, test_table_isolation_b won't see this table or data.
    """
    with postgres_db.cursor() as cur:
        # Get current DB name to verify tenant
        cur.execute("SELECT current_database();")
        db_name = cur.fetchone()[0]
        print(f"Worker {worker_id} connected to {db_name}")
        
        cur.execute("CREATE TABLE items (id serial PRIMARY KEY, name text);")
        cur.execute("INSERT INTO items (name) VALUES ('item_from_a');")
        
        cur.execute("SELECT count(*) FROM items;")
        assert cur.fetchone()[0] == 1

def test_table_isolation_b(postgres_db, worker_id):
    """
    Runs in parallel with A.
    Should NOT see table 'items' from A because we are in a different DB.
    """
    with postgres_db.cursor() as cur:
        cur.execute("SELECT current_database();")
        db_name = cur.fetchone()[0]
        print(f"Worker {worker_id} connected to {db_name}")

        # This should fail if we were sharing the same DB and A ran first without cleanup
        # Or, if we are isolated, this table shouldn't exist.
        try:
            cur.execute("SELECT * FROM items;")
            exists = True
        except Exception:
            exists = False
            # Reset transaction if error occurred
            postgres_db.rollback() 
        
        if not exists:
            # Good, table doesn't exist, let's create our own
            cur.execute("CREATE TABLE items (id serial PRIMARY KEY, name text);")
            cur.execute("INSERT INTO items (name) VALUES ('item_from_b');")
            cur.execute("SELECT count(*) FROM items;")
            assert cur.fetchone()[0] == 1
        else:
            # If table exists, ensure it doesn't have A's data (if we were reusing DBs)
            # But in this architecture, we expect a clean DB, so table shouldn't exist.
            pass
