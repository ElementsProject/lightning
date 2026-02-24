from utils import TEST_NETWORK, VALGRIND  # noqa: F401,F403
from pyln.testing.fixtures import directory, test_base_dir, test_name, chainparams, node_factory, bitcoind, teardown_checks, db_provider, executor, setup_logging, jsonschemas  # noqa: F401,F403
from pyln.testing import utils
from utils import COMPAT
from pathlib import Path

import os
import pytest
import re
import shutil
import subprocess
import tempfile
import time
from pyln.testing.utils import env
from vls import ValidatingLightningSignerD


@pytest.fixture
def node_cls():
    return LightningNode


class LightningNode(utils.LightningNode):
    def __init__(self, *args, **kwargs):
        # Yes, we really want to test the local development version, not
        # something in out path.
        kwargs["executable"] = "lightningd/lightningd"
        utils.LightningNode.__init__(self, *args, **kwargs)

        # New VLS integration
        mode = env("VLS_MODE", "cln:native")

        subdaemon = {
            "cln:native": None,
            "cln:socket": "path/to/vls/artifact"
        }[mode]

        if subdaemon:
            self.REQUEST = None
            self.use_vlsd = self.subdaemon is not None
            self.vlsd: ValidatingLightningSignerD | None = None
            self.vls_dir = self.lightning_dir / "vlsd"
            self.vlsd_port = utils.reserve_unused_port()
            self.vlsd_rpc_port = utils.reserve_unused_port()
            self.daemon.opts["subdaemon"] = subdaemon

        # Avoid socket path name too long on Linux
        if os.uname()[0] == 'Linux' and \
                len(str(self.lightning_dir / TEST_NETWORK / 'lightning-rpc')) >= 108:
            self.daemon.opts['rpc-file'] = '/proc/self/cwd/lightning-rpc'

        # This is a recent innovation, and we don't want to nail pyln-testing to this version.
        self.daemon.opts['dev-crash-after'] = 3600

        # We have some valgrind suppressions in the `tests/`
        # directory, so we can add these to the valgrind configuration
        # (not generally true when running pyln-testing, hence why
        # it's being done in this specialization, and not in the
        # library).
        if self.daemon.cmd_line[0] == 'valgrind':
            suppressions_path = Path(__file__).parent / "valgrind-suppressions.txt"
            self.daemon.cmd_prefix += [
                f"--suppressions={suppressions_path}",
                "--gen-suppressions=all"
            ]

        # If we opted into checking the DB statements we will attach the dblog
        # plugin before starting the node
        check_dblog = os.environ.get("TEST_CHECK_DBSTMTS", None) == "1"
        db_type = os.environ.get("TEST_DB_PROVIDER", "sqlite3")
        if db_type == 'sqlite3' and check_dblog:
            dblog = os.path.join(os.path.dirname(__file__), 'plugins', 'dblog.py')
            has_dblog = len([o for o in self.daemon.cmd_line if 'dblog.py' in o]) > 0
            if not has_dblog:
                # Add as an expanded option so we don't clobber other options.
                self.daemon.opts['plugin={}'.format(dblog)] = None
                self.daemon.opts['dblog-file'] = 'dblog.sqlite3'

        if db_type == 'postgres' and ('disable-plugin', 'bookkeeper') not in self.daemon.opts.items():
            accts_db = self.db.provider.get_db('', 'accounts', 0)
            self.daemon.opts['bookkeeper-db'] = accts_db.get_dsn()

        def start(self, wait_for_bitcoind_sync=True, stderr_redir=False):
            self.vls_dir.mkdir(exist_ok=True, parents=True)

            # We start the signer first, otherwise the lightningd startup hangs on the init message
            if self.use_vlsd:
                self.daemon.env["VLS_PORT"] = str(self.vlsd_port)
                self.daemon.env["VLS_LSS"] = os.environ.get("LSS_URI", "")
                self.vlsd = ValidatingLightningSignerD(
                    vlsd_dir=self.vls_dir,
                    vlsd_port=self.vlsd_port,
                    vlsd_rpc_port=self.vlsd_rpc_port,
                    node_id=self.node_id,
                    network=self.network,
                )
                import threading

                threading.Timer(1, self.vlsd.start).start()
                self.REQUEST.addfinalizer(self.vlsd.stop)

            self.start(
                self,
                wait_for_bitcoind_sync=wait_for_bitcoind_sync,
                stderr_redir=stderr_redir,
            )



class CompatLevel(object):
    """An object that encapsulates the compat-level of our build.
    """
    def __init__(self):
        makefile = os.path.join(os.path.dirname(__file__), "..", "Makefile")
        with open(makefile, 'r') as f:
            lines = [l for l in f if l.startswith('COMPAT_CFLAGS')]
        assert(len(lines) == 1)
        line = lines[0]
        flags = re.findall(r'COMPAT_V([0-9]+)=1', line)
        self.compat_flags = flags

    def __call__(self, version):
        return COMPAT and version in self.compat_flags


@pytest.fixture
def compat():
    return CompatLevel()


def is_compat(version):
    compat = CompatLevel()
    return compat(version)


def dumpcap_usable():
    def have_binary(name):
        return shutil.which(name) is not None

    if not have_binary("dumpcap") or not have_binary("tshark"):
        return False

    try:
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "probe.pcap"

            proc = subprocess.Popen(
                [
                    "dumpcap",
                    "-i", "lo",
                    "-w", str(pcap),
                    "-f", "tcp",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(0.2)
            proc.terminate()
            proc.wait(timeout=1)

            return pcap.exists() and pcap.stat().st_size > 0
    except (PermissionError, subprocess.SubprocessError, OSError):
        return False


@pytest.fixture(scope="session")
def have_pcap_tools():
    if not dumpcap_usable():
        pytest.skip("dumpcap/tshark not available or insufficient privileges")


class TcpCapture:
    def __init__(self, tmpdir):
        self.tmpdir = Path(tmpdir)
        self.pcap = self.tmpdir / "traffic.pcap"
        self.proc = None
        self.port = None

    def start(self, port):
        assert self.proc is None, "capture already started"
        self.port = int(port)

        self.proc = subprocess.Popen(
            [
                "dumpcap",
                "-i", "lo",
                "-w", str(self.pcap),
                "-f", f"tcp port {self.port}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # allow filter attach
        time.sleep(0.2)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=2)
            self.proc = None

    def assert_constant_payload(self):
        tshark_cmd = [
            "tshark",
            "-r", str(self.pcap),
            "-Y", "tcp.len > 0",
            "-T", "fields",
            "-e", "tcp.len",
        ]

        out = subprocess.check_output(tshark_cmd, text=True)
        lengths = [int(x) for x in out.splitlines() if x.strip()]

        assert lengths, f"No TCP payload packets captured on port {self.port}"

        uniq = set(lengths)
        assert len(uniq) == 1, (
            f"Non-constant TCP payload sizes on port {self.port}: "
            f"{sorted(uniq)}:"
            + subprocess.check_output(["tshark", "-r", str(self.pcap)], text=True)
        )


@pytest.fixture
def tcp_capture(have_pcap_tools, tmp_path):
    # You will need permissions.  Most distributions have a group which has
    # permissions to use dumpcap:
    #     $ ls -l /usr/bin/dumpcap
    #     -rwxr-xr-- 1 root wireshark 229112 Apr 16  2024 /usr/bin/dumpcap
    #     $ getcap /usr/bin/dumpcap
    #     /usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
    # So you just need to be in the wireshark group.
    cap = TcpCapture(tmp_path)
    yield cap
    cap.stop()
    cap.assert_constant_payload()
