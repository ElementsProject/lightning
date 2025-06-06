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
import time
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse


class BaseDb(object):
    def wipe_db(self):
        raise NotImplementedError("wipe_db method must be implemented by the subclass")


class Sqlite3Db(BaseDb):
    def __init__(self, path: str) -> None:
        self.path = path
        self.provider = None

    def get_dsn(self) -> None:
        """SQLite3 doesn't provide a DSN, resulting in no CLI-option."""
        return None

    def query(
        self, query: str
    ) -> Union[
        List[Dict[str, Union[int, bytes]]],
        List[Dict[str, Optional[int]]],
        List[Dict[str, str]],
        List[Dict[str, Union[str, int]]],
        List[Dict[str, int]],
    ]:
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

    def execute(self, query: str) -> None:
        db = sqlite3.connect(self.path)
        c = db.cursor()
        c.execute(query)
        db.commit()
        c.close()
        db.close()

    def stop(self):
        pass

    def wipe_db(self):
        if os.path.exists(self.path):
            os.remove(self.path)


class PostgresDb(BaseDb):
    def __init__(self, dbname, hostname, port, username, password):
        self.dbname = dbname
        self.port = port
        self.provider = None
        self.hostname = hostname
        self.username = username
        self.password = password

        self.conn = psycopg2.connect(
            f"dbname={dbname} user={username} password={password} host={hostname} port={port}"
        )
        cur = self.conn.cursor()
        cur.execute("SELECT 1")
        cur.close()

    def get_dsn(self):
        return f"postgres://{self.username}:{self.password}@{self.hostname}:{self.port}/{self.dbname}"

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

    def execute(self, query):
        with self.conn, self.conn.cursor() as cur:
            cur.execute(query)

    def stop(self):
        """Clean up the database."""
        self.conn.close()
        conn = psycopg2.connect(
            f"dbname=postgres user={self.username} host={self.hostname} password={self.password} port={self.port}"
        )
        cur = conn.cursor()
        cur.execute("DROP DATABASE {};".format(self.dbname))
        cur.close()

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
        path = os.path.join(node_directory, "lightningd.sqlite3")
        return Sqlite3Db(path)

    def stop(self) -> None:
        pass


class PostgresDbProvider(object):
    def __init__(self, directory):
        self.directory = directory
        self.port = None
        self.proc = None
        self.hostname = "127.0.0.1"  # We default to localhost, but can be overridden
        self.username = "postgres"
        self.password = "postgres"

        print("Starting PostgresDbProvider")

    def locate_path(self):
        # Use `pg_config` to determine correct PostgreSQL installation
        pg_config = shutil.which("pg_config")
        if not pg_config:
            raise ValueError(
                "Could not find `pg_config` to determine PostgreSQL binaries. Is PostgreSQL installed?"
            )

        bindir = subprocess.check_output([pg_config, "--bindir"]).decode().rstrip()
        if not os.path.isdir(bindir):
            raise ValueError(
                "Error: `pg_config --bindir` didn't return a proper path: {}".format(
                    bindir
                )
            )

        initdb = os.path.join(bindir, "initdb")
        postgres = os.path.join(bindir, "postgres")
        if os.path.isfile(initdb) and os.path.isfile(postgres):
            if os.access(initdb, os.X_OK) and os.access(postgres, os.X_OK):
                logging.info("Found `postgres` and `initdb` in {}".format(bindir))
                return initdb, postgres

        raise ValueError(
            "Could not find `postgres` and `initdb` binaries in {}".format(bindir)
        )

    def start(self):
        passfile = os.path.join(self.directory, "pgpass.txt")
        # Need to write a tiny file containing the password so `initdb` can
        # pick it up
        with open(passfile, "w") as f:
            f.write("cltest\n")

        # Look for a postgres directory that isn't taken yet. Not locking
        # since this is run in a single-threaded context, at the start of each
        # test. Multiple workers have separate directories, so they can't
        # trample each other either.
        for i in itertools.count():
            self.pgdir = os.path.join(self.directory, "pgsql-{}".format(i))
            if not os.path.exists(self.pgdir):
                break

        initdb, postgres = self.locate_path()
        subprocess.check_call(
            [
                initdb,
                "--pwfile={}".format(passfile),
                "--pgdata={}".format(self.pgdir),
                "--auth=trust",
                "--username=postgres",
            ]
        )
        conffile = os.path.join(self.pgdir, "postgresql.conf")
        with open(conffile, "a") as f:
            f.write("max_connections = 1000\nshared_buffers = 240MB\n")

        self.port = reserve_unused_port()
        self.proc = subprocess.Popen(
            [
                postgres,
                "-k",
                "/tmp/",  # So we don't use /var/lib/...
                "-D",
                self.pgdir,
                "-p",
                str(self.port),
                "-F",
                "-i",
            ]
        )
        # Hacky but seems to work ok (might want to make the postgres proc a
        # TailableProc as well if too flaky).
        for i in range(30):
            try:
                self.conn = psycopg2.connect(
                    "dbname=template1 user=postgres host=localhost port={}".format(
                        self.port
                    )
                )
                break
            except Exception:
                time.sleep(0.5)

        # Required for CREATE DATABASE to work
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def get_db(self, node_directory, testname, node_id):
        # Random suffix to avoid collisions on repeated tests
        nonce = "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
        )
        dbname = "{}_{}_{}".format(testname, node_id, nonce)

        cur = self.conn.cursor()
        cur.execute("CREATE DATABASE {};".format(dbname))
        cur.close()
        db = PostgresDb(dbname, self.hostname, self.port, self.username, self.password)
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


class SystemPostgresDbProvider(PostgresDbProvider):
    """A DB provider that uses an externally controlled postgres instance.

    Spinning postgres instances up and down is costly. We are keeping
    tests separate by assigning them random names, so we can share a
    single DB cluster. This provider does just that: it talks to an
    externally managed cluster, creates and deletes DBs on demand, but
    does not manage the cluster's lifecycle.

    The external cluster to talk to can be specified via the
    `CLN_TEST_POSTGRES_DSN` environment variable.

    Please make sure that the user specified in the DSN has the
    permission to create new DBs.

    Since tests, may end up interrupted, and may not clean up the
    databases they created, be aware that over time your cluster may
    accumulate quite a few databases. This mode is mostly intended for
    CI where a throwaway postgre cluster can be spun up and tested
    against.

    """

    def __init__(self, directory):
        self.dsn = os.environ.get("CLN_TEST_POSTGRES_DSN")
        self.conn = None
        parts = urlparse(self.dsn)

        self.hostname = parts.hostname
        self.username = parts.username
        self.password = parts.password if parts.password else ""
        self.port = parts.port if parts.port else 5432
        self.dbname = parts.path

    def stop(self):
        pass

    def start(self):
        self.conn = psycopg2.connect(self.dsn)
        cur = self.conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        # Required for CREATE DATABASE to work
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
