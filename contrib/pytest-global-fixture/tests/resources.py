import time
import psycopg2
from psycopg2 import sql
from testcontainers.postgres import PostgresContainer
from pytest_global_fixture.base import InfrastructureService


class PostgresService(InfrastructureService):
    def __init__(self):
        self.container = None
        self.master_config = {}

    def start_global(self) -> None:
        """
        Starts a single Postgres Docker container.
        """
        print(">> [Service] Starting Postgres Container...")
        time.sleep(30)
        self.container = PostgresContainer("postgres:15-alpine")
        self.container.start()

        # Connection info for the Superuser
        self.master_config = {
            "host": self.container.get_container_host_ip(),
            "port": self.container.get_exposed_port(5432),
            "user": self.container.username,
            "password": self.container.password,
            "dbname": self.container.dbname,
        }

        # Wait for readiness
        self._wait_for_ready()

    def stop_global(self) -> None:
        if self.container:
            time.sleep(30)
            print(">> [Service] Stopping Postgres Container...")
            self.container.stop()

    def create_tenant(self, tenant_id: str) -> dict:
        """
        Creates a new DATABASE for the specific test/worker.
        """
        # Connect as superuser to create a new DB
        conn = psycopg2.connect(**self.master_config)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                # Sanitize the tenant_id slightly for SQL (simple alphanumeric check is best)
                safe_name = tenant_id.replace("-", "_")
                cur.execute(
                    sql.SQL("CREATE DATABASE {}").format(sql.Identifier(safe_name))
                )
        finally:
            conn.close()

        # Return config pointing to the NEW database
        tenant_config = self.master_config.copy()
        tenant_config["dbname"] = tenant_id.replace("-", "_")
        return tenant_config

    def remove_tenant(self, tenant_id: str) -> None:
        """
        Drops the tenant database.
        """
        conn = psycopg2.connect(**self.master_config)
        conn.autocommit = True
        safe_name = tenant_id.replace("-", "_")
        try:
            with conn.cursor() as cur:
                # Force disconnect users before dropping
                cur.execute(
                    sql.SQL("""
                    SELECT pg_terminate_backend(pg_stat_activity.pid)
                    FROM pg_stat_activity
                    WHERE pg_stat_activity.datname = {}
                    AND pid <> pg_backend_pid();
                """).format(sql.Literal(safe_name))
                )

                cur.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {}").format(
                        sql.Identifier(safe_name)
                    )
                )
        finally:
            conn.close()

    def _wait_for_ready(self):
        # Basic check
        retries = 5
        while retries > 0:
            try:
                conn = psycopg2.connect(**self.master_config)
                conn.close()
                return
            except Exception:
                time.sleep(1)
                retries -= 1
        raise RuntimeError("Postgres failed to start")
