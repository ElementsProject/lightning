from .utils import reserve_unused_port, drop_unused_port

import itertools
import logging
import os
import psycopg2  # type: ignore
import random
import shutil
import signal
import sqlite3
import string
import subprocess
import threading
import time
from typing import Dict, List, Optional, Union


class BaseDb(object):
    def wipe_db(self):
        raise NotImplementedError("wipe_db method must be implemented by the subclass")


class Sqlite3Db(BaseDb):
    def __init__(self, path: str) -> None:
        self.path = path
        self.provider = None

    def get_dsn(self) -> None:
        """SQLite3 doesn't provide a DSN, resulting in no CLI-option.
        """
        return None

    def query(self, query: str) -> Union[List[Dict[str, Union[int, bytes]]], List[Dict[str, Optional[int]]], List[Dict[str, str]], List[Dict[str, Union[str, int]]], List[Dict[str, int]]]:
        orig = os.path.join(self.path)
        copy = self.path + ".copy"
        shutil.copyfile(orig, copy)
        db = sqlite3.connect(copy)

        db.row_factory = sqlite3.Row
        c = db.cursor()
        # Don't get upset by concurrent writes; wait for up to 5 seconds!
        c.execute("PRAGMA busy_timeout = 5000")
        c.execute(query)
        rows = c.fetchall()

        result = []
        for row in rows:
            result.append(dict(zip(row.keys(), row)))

        db.commit()
        c.close()
        db.close()
        return result

    def execute(self, query: str, params: tuple = ()) -> None:
        """Execute a single statement with bound params. Placeholders: '?'"""
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA busy_timeout = 5000")
            db.execute(query, params)

    def executemany(self, query: str, seq_of_params: list[tuple]) -> None:
        """Batch execute with bound params. Placeholders: '?'"""
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA busy_timeout = 5000")
            db.executemany(query, seq_of_params)

    def stop(self):
        pass

    def wipe_db(self):
        if os.path.exists(self.path):
            os.remove(self.path)


class PostgresDb(BaseDb):
    def __init__(self, dbname, port):
        self.dbname = dbname
        self.port = port
        self.provider = None
        self._conn = None

    @property
    def conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(
                f"dbname={self.dbname} user=postgres host=localhost port={self.port}"
            )
        return self._conn

    def get_dsn(self):
        return "postgres://postgres:password@localhost:{port}/{dbname}".format(
            port=self.port, dbname=self.dbname
        )

    def query(self, query):
        cur = self.conn.cursor()
        cur.execute(query)

        # Collect the results into a list of dicts.
        res = []
        for r in cur:
            t = {}
            # Zip the column definition with the value to get its name.
            for c, v in zip(cur.description, r):
                t[c.name] = v
            res.append(t)
        cur.close()
        return res

    def execute(self, query: str, params: tuple = ()) -> None:
        """Execute a single statement with bound params. Placeholders: '%s'"""
        with self.conn, self.conn.cursor() as cur:
            cur.execute(query, params)

    def executemany(self, query: str, seq_of_params: list[tuple]) -> None:
        """Batch execute with bound params. Placeholders: '%s'"""
        with self.conn, self.conn.cursor() as cur:
            cur.executemany(query.replace('?', '%s'), seq_of_params)

    def stop(self):
        """Clean up the database.
        """
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None
        if self.provider is not None:
            self.provider.drop_db(self.dbname)
            return
        conn = psycopg2.connect(f"dbname=postgres user=postgres host=localhost port={self.port}")
        try:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {self.dbname};")
        finally:
            conn.close()

    def wipe_db(self):
        cur = self.conn.cursor()
        cur.execute(f"DROP DATABASE IF EXISTS {self.dbname};")
        cur.execute(f"CREATE DATABASE {self.dbname};")
        cur.close()


class SqliteDbProvider(object):
    def __init__(self, directory: str) -> None:
        self.directory = directory

    def start(self) -> None:
        pass

    def get_db(self, node_directory: str, testname: str, node_id: int) -> Sqlite3Db:
        path = os.path.join(
            node_directory,
            'lightningd.sqlite3'
        )
        return Sqlite3Db(path)

    def drop_db(self, dbname: str) -> None:
        pass

    def stop(self) -> None:
        pass


class ScopedDbProvider(object):
    """Per-test wrapper around a session-scoped DbProvider that cleans up
    databases created during a single test."""

    def __init__(self, provider) -> None:
        self._provider = provider
        self._lock = threading.Lock()
        self._dbs: List[BaseDb] = []

    def get_db(self, node_directory: str, testname: str, node_id: int):
        db = self._provider.get_db(node_directory, testname, node_id)
        db.provider = self
        with self._lock:
            self._dbs.append(db)
        return db

    def drop_db(self, dbname: str) -> None:
        self._provider.drop_db(dbname)

    def cleanup(self) -> None:
        with self._lock:
            dbs, self._dbs = self._dbs, []
        for db in dbs:
            db.stop()

    def __getattr__(self, name):
        return getattr(self._provider, name)


class PostgresDbProvider(object):
    # Postgres truncates identifiers at NAMEDATALEN - 1 bytes.
    MAX_IDENTIFIER_LEN = 63

    def __init__(self, directory):
        self.directory = directory
        self.port = None
        self.proc = None
        self.conn = None
        self.lock = threading.Lock()
        print("Starting PostgresDbProvider")

    def locate_path(self):
        # Use `pg_config` to determine correct PostgreSQL installation
        pg_config = shutil.which('pg_config')
        if not pg_config:
            raise ValueError("Could not find `pg_config` to determine PostgreSQL binaries. Is PostgreSQL installed?")

        bindir = subprocess.check_output([pg_config, '--bindir']).decode().rstrip()
        if not os.path.isdir(bindir):
            raise ValueError("Error: `pg_config --bindir` didn't return a proper path: {}".format(bindir))

        initdb = os.path.join(bindir, 'initdb')
        postgres = os.path.join(bindir, 'postgres')
        if os.path.isfile(initdb) and os.path.isfile(postgres):
            if os.access(initdb, os.X_OK) and os.access(postgres, os.X_OK):
                logging.info("Found `postgres` and `initdb` in {}".format(bindir))
                return initdb, postgres

        raise ValueError("Could not find `postgres` and `initdb` binaries in {}".format(bindir))

    def start(self):
        passfile = os.path.join(self.directory, "pgpass.txt")
        # Need to write a tiny file containing the password so `initdb` can
        # pick it up
        with open(passfile, 'w') as f:
            f.write('cltest\n')

        # Look for a postgres directory that isn't taken yet. Not locking
        # since this is run in a single-threaded context, at the start of each
        # test. Multiple workers have separate directories, so they can't
        # trample each other either.
        for i in itertools.count():
            self.pgdir = os.path.join(self.directory, 'pgsql-{}'.format(i))
            if not os.path.exists(self.pgdir):
                break

        initdb, postgres = self.locate_path()
        subprocess.check_call([
            initdb,
            '--pwfile={}'.format(passfile),
            '--pgdata={}'.format(self.pgdir),
            '--auth=trust',
            '--username=postgres',
        ])
        conffile = os.path.join(self.pgdir, 'postgresql.conf')
        with open(conffile, 'a') as f:
            f.write(
                'max_connections = 1000\n'
                'shared_buffers = 240MB\n'
                'synchronous_commit = off\n'
                'full_page_writes = off\n'
                'checkpoint_timeout = 30min\n'
            )

        self.port = reserve_unused_port()
        self.proc = subprocess.Popen([
            postgres,
            '-k', '/tmp/',  # So we don't use /var/lib/...
            '-D', self.pgdir,
            '-p', str(self.port),
            '-F',
            '-i',
        ])
        # Hacky but seems to work ok (might want to make the postgres proc a
        # TailableProc as well if too flaky).
        last_err = None
        for i in range(300):
            try:
                self.conn = psycopg2.connect("dbname=template1 user=postgres host=localhost port={}".format(self.port))
                break
            except Exception as e:
                last_err = e
                time.sleep(0.05)
        if self.conn is None:
            raise last_err

        # Required for CREATE DATABASE to work
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    @staticmethod
    def db_name(testname: str, node_id: int, nonce: str) -> str:
        """Build the database name for a node of a test.

        Truncates the testname, not the suffix: postgres would otherwise
        cut off the node_id and the nonce, making the names of
        long-named tests collide and fail with `DuplicateDatabase`.
        """
        suffix = "_{}_{}".format(node_id, nonce)
        return testname[:PostgresDbProvider.MAX_IDENTIFIER_LEN - len(suffix)] + suffix

    def get_db(self, node_directory, testname, node_id):
        # Random suffix to avoid collisions on repeated tests
        nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        dbname = self.db_name(testname, node_id, nonce)

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("CREATE DATABASE {};".format(dbname))
            cur.close()
        db = PostgresDb(dbname, self.port)
        return db

    def drop_db(self, dbname):
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(f"DROP DATABASE IF EXISTS {dbname};")
            except psycopg2.Error:
                # Terminate any lingering connections (e.g. after a failed test) and retry.
                cur.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid();",
                    (dbname,),
                )
                cur.execute(f"DROP DATABASE IF EXISTS {dbname};")
            finally:
                cur.close()

    def stop(self):
        # Send fast shutdown signal see [1] for details:
        #
        # SIGINT
        #
        # This is the Fast Shutdown mode. The server disallows new connections
        # and sends all existing server processes SIGTERM, which will cause
        # them to abort their current transactions and exit promptly. It then
        # waits for all server processes to exit and finally shuts down. If
        # the server is in online backup mode, backup mode will be terminated,
        # rendering the backup useless.
        #
        # [1] https://www.postgresql.org/docs/9.1/server-shutdown.html
        if self.conn is not None and not self.conn.closed:
            self.conn.close()
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait()
        shutil.rmtree(self.pgdir)
        drop_unused_port(self.port)
