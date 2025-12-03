"""
Production-ready PostgreSQL service using native binaries.
This service starts a real PostgreSQL instance using initdb and postgres binaries,
similar to how pyln-testing's PostgresDbProvider works, but as a globally shared resource.
"""
import itertools
import logging
import os
import psycopg2
import shutil
import signal
import subprocess
import tempfile
import time
from psycopg2 import sql
from typing import Dict
from .base import InfrastructureService


class NativePostgresService(InfrastructureService):
    """
    PostgreSQL service using native postgres/initdb binaries.
    Starts one PostgreSQL instance globally and creates separate databases per tenant.
    """

    def __init__(self, base_dir: str = None):
        """
        Args:
            base_dir: Directory to store postgres data. If None, uses tempfile.
        """
        self.base_dir = base_dir
        self.pgdir = None
        self.port = None
        self.proc = None
        self.conn = None
        self.master_config = {}

    def _locate_postgres_binaries(self):
        """Find PostgreSQL binaries using pg_config."""
        pg_config = shutil.which('pg_config')
        if not pg_config:
            raise ValueError(
                "Could not find `pg_config` to determine PostgreSQL binaries. "
                "Is PostgreSQL installed?"
            )

        bindir = subprocess.check_output([pg_config, '--bindir']).decode().rstrip()
        if not os.path.isdir(bindir):
            raise ValueError(
                f"Error: `pg_config --bindir` didn't return a proper path: {bindir}"
            )

        initdb = os.path.join(bindir, 'initdb')
        postgres = os.path.join(bindir, 'postgres')

        if os.path.isfile(initdb) and os.path.isfile(postgres):
            if os.access(initdb, os.X_OK) and os.access(postgres, os.X_OK):
                logging.info(f"Found `postgres` and `initdb` in {bindir}")
                return initdb, postgres

        raise ValueError(
            f"Could not find `postgres` and `initdb` binaries in {bindir}"
        )

    def _reserve_port(self):
        """Reserve an unused port for PostgreSQL."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def start_global(self) -> None:
        """Initialize and start the PostgreSQL instance."""
        print(">> [NativePostgresService] Starting PostgreSQL instance...")

        # Create base directory
        if self.base_dir is None:
            self.base_dir = tempfile.mkdtemp(prefix='pytest-postgres-')
        else:
            os.makedirs(self.base_dir, exist_ok=True)

        # Find an unused postgres data directory
        for i in itertools.count():
            self.pgdir = os.path.join(self.base_dir, f'pgsql-{i}')
            if not os.path.exists(self.pgdir):
                break

        # Create password file for initdb
        passfile = os.path.join(self.base_dir, "pgpass.txt")
        with open(passfile, 'w') as f:
            f.write('postgres\n')

        # Initialize the database cluster
        initdb, postgres = self._locate_postgres_binaries()
        subprocess.check_call([
            initdb,
            f'--pwfile={passfile}',
            f'--pgdata={self.pgdir}',
            '--auth=trust',
            '--username=postgres',
        ])

        # Configure postgres for high connection count
        conffile = os.path.join(self.pgdir, 'postgresql.conf')
        with open(conffile, 'a') as f:
            f.write('max_connections = 1000\n')
            f.write('shared_buffers = 240MB\n')

        # Reserve a port and start postgres
        self.port = self._reserve_port()
        self.proc = subprocess.Popen([
            postgres,
            '-k', '/tmp/',  # Unix socket directory
            '-D', self.pgdir,
            '-p', str(self.port),
            '-F',  # No fsync (faster, ok for tests)
            '-i',  # Listen on TCP
        ])

        # Wait for postgres to be ready
        self._wait_for_ready()

        # Connect to template1 for database operations
        self.conn = psycopg2.connect(
            f"dbname=template1 user=postgres host=localhost port={self.port}"
        )
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        # Store master config for creating databases
        self.master_config = {
            "host": "localhost",
            "port": self.port,
            "user": "postgres",
            "dbname": "template1"
        }

        print(f">> [NativePostgresService] PostgreSQL started on port {self.port}")

    def _wait_for_ready(self):
        """Wait for PostgreSQL to be ready to accept connections."""
        for i in range(30):
            try:
                test_conn = psycopg2.connect(
                    f"dbname=template1 user=postgres host=localhost port={self.port}"
                )
                test_conn.close()
                return
            except Exception:
                time.sleep(0.5)

        raise RuntimeError("PostgreSQL failed to start within timeout")

    def stop_global(self) -> None:
        """Stop the PostgreSQL instance and clean up."""
        print(">> [NativePostgresService] Stopping PostgreSQL instance...")

        if self.conn:
            self.conn.close()

        if self.proc:
            # Fast shutdown: SIGINT
            self.proc.send_signal(signal.SIGINT)
            self.proc.wait()

        if self.pgdir and os.path.exists(self.pgdir):
            shutil.rmtree(self.pgdir)

        print(">> [NativePostgresService] PostgreSQL stopped")

    def create_tenant(self, tenant_id: str) -> Dict:
        """
        Create an isolated database for a tenant.

        Args:
            tenant_id: Unique identifier for the tenant

        Returns:
            Dictionary with connection parameters: host, port, user, dbname
        """
        # Sanitize database name (postgres doesn't like dashes in identifiers)
        safe_name = tenant_id.replace("-", "_")

        with self.conn.cursor() as cur:
            cur.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(safe_name))
            )

        # Return connection config for the tenant database
        return {
            "host": "localhost",
            "port": self.port,
            "user": "postgres",
            "dbname": safe_name
        }

    def remove_tenant(self, tenant_id: str) -> None:
        """
        Drop the tenant database.

        Args:
            tenant_id: Unique identifier for the tenant
        """
        safe_name = tenant_id.replace("-", "_")

        with self.conn.cursor() as cur:
            # Terminate any active connections to the database
            cur.execute(sql.SQL("""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = {}
                AND pid <> pg_backend_pid()
            """).format(sql.Literal(safe_name)))

            # Drop the database
            cur.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(safe_name))
            )
