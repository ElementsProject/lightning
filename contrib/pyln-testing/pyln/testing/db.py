from .utils import reserve_unused_port, drop_unused_port
from urllib.parse import urlparse, urlunparse

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
import time
from typing import Dict, List, Optional, Union


def replace_dsn_database(dsn: str, dbname: str) -> str:
    """Replace the database name in a PostgreSQL DSN.

    Takes a DSN like 'postgres://user:pass@host:port/olddb' and returns
    'postgres://user:pass@host:port/newdb'.
    """
    parsed = urlparse(dsn)
    # Replace path (database name) with the new one
    new_parsed = parsed._replace(path=f"/{dbname}")
    return urlunparse(new_parsed)


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
    def __init__(self, dbname, port, base_dsn=None):
        self.dbname = dbname
        self.port = port
        self.base_dsn = base_dsn
        self.provider = None

        if base_dsn:
            # Connect using base DSN but with our specific database
            self.conn = psycopg2.connect(replace_dsn_database(base_dsn, dbname))
        else:
            self.conn = psycopg2.connect("dbname={dbname} user=postgres host=localhost port={port}".format(
                dbname=dbname, port=port
            ))
        cur = self.conn.cursor()
        cur.execute('SELECT 1')
        cur.close()

    def get_dsn(self):
        if self.base_dsn:
            return replace_dsn_database(self.base_dsn, self.dbname)
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
        self.conn.close()
        if self.base_dsn:
            conn = psycopg2.connect(self.base_dsn)
        else:
            conn = psycopg2.connect(f"dbname=postgres user=postgres host=localhost port={self.port}")
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("DROP DATABASE {};".format(self.dbname))
        cur.close()
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

    def stop(self) -> None:
        pass


class PostgresDbProvider(object):
    def __init__(self, directory):
        self.directory = directory
        self.port = None
        self.proc = None
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
            f.write('max_connections = 1000\nshared_buffers = 240MB\n')

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
        for i in range(30):
            try:
                self.conn = psycopg2.connect("dbname=template1 user=postgres host=localhost port={}".format(self.port))
                break
            except Exception:
                time.sleep(0.5)

        # Required for CREATE DATABASE to work
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def get_db(self, node_directory, testname, node_id):
        # Random suffix to avoid collisions on repeated tests
        nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        dbname = "{}_{}_{}".format(testname, node_id, nonce)

        cur = self.conn.cursor()
        cur.execute("CREATE DATABASE {};".format(dbname))
        cur.close()
        db = PostgresDb(dbname, self.port)
        return db

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
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait()
        shutil.rmtree(self.pgdir)
        drop_unused_port(self.port)


class SystemPostgresDbProvider(object):
    """Use an existing system-wide PostgreSQL instance instead of spawning one.

    This provider connects to an existing PostgreSQL server using a DSN from
    the TEST_DB_PROVIDER_DSN environment variable. The DSN should point to a
    database where the user has CREATE DATABASE privileges (typically the
    'postgres' database with a superuser).

    Example DSN: postgres://postgres:password@localhost:5432/postgres
    """

    def __init__(self, directory):
        self.directory = directory
        self.dsn = os.environ.get('TEST_DB_PROVIDER_DSN')
        if not self.dsn:
            raise ValueError(
                "SystemPostgresDbProvider requires TEST_DB_PROVIDER_DSN environment variable"
            )
        self.conn = None

    def start(self):
        self.conn = psycopg2.connect(self.dsn)
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        logging.info(f"Connected to system PostgreSQL via {self.dsn}")

    def get_db(self, node_directory, testname, node_id):
        # Random suffix to avoid collisions on repeated tests
        nonce = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        dbname = "{}_{}_{}".format(testname, node_id, nonce)

        cur = self.conn.cursor()
        cur.execute("CREATE DATABASE {};".format(dbname))
        cur.close()
        db = PostgresDb(dbname, port=None, base_dsn=self.dsn)
        return db

    def stop(self):
        if self.conn:
            self.conn.close()
