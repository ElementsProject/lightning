from pyln.testing.utils import TailableProc, env, reserve_unused_port
from pathlib import Path
from subprocess import run
import logging
import os


REPOS = ["https://gitlab.com/lightning-signer/validating-lightning-signer.git"]


def _resolve_executable(datadir: Path) -> Path:
    """
    Return the path where the vlsd executable can be found.
    """
    prebuilt = os.environ.get("REMOTE_SIGNER_PATH")
    if prebuilt:
        path = Path(os.path.expanduser(prebuilt)).resolve()
        if not path.exists():
            raise RuntimeError(f"REMOTE_SIGNER_PATH={prebuilt} does not exist")
        return path

    if os.environ.get("VLS_AUTO_BUILD") != "1":
        raise RuntimeError(
            "No VLS binary available: set REMOTE_SIGNER_PATH to a pre-built "
            "vlsd, or VLS_AUTO_BUILD=1 to clone and compile it."
        )

    signer_folder = REPOS[0].split("/")[-1].removesuffix(".git")
    vlsd_dir = (datadir / signer_folder).resolve()
    logging.info(f"Cloning {REPOS[0]} into {vlsd_dir}")
    run(["git", "clone", REPOS[0]], cwd=datadir, check=True, timeout=120)
    logging.info(f"Building vlsd in {vlsd_dir}")
    run(["cargo", "build", "--features", "developer"],
        cwd=vlsd_dir, check=True, timeout=600)
    return (vlsd_dir / "target" / "debug" / "vlsd").resolve()


class ValidatingLightningSignerD(TailableProc):
    def __init__(self, lightning_dir, node_id, network):
        # Each node gets its own datadir and socket, so multiple nodes can run
        # their own signer in parallel even when sharing a prebuilt binary.
        self.datadir = (Path(lightning_dir) / "vlsd").resolve()
        self.datadir.mkdir(exist_ok=True, parents=True)

        self.bin_dir = str(_resolve_executable(self.datadir))
        self.executable = self.bin_dir + "/vlsd"
        self.port = reserve_unused_port()
        self.rpc_port = reserve_unused_port()
        self.remote_socket = (Path(self.bin_dir) / "remote_hsmd_socket").resolve()
        if not self.remote_socket.exists():
            raise RuntimeError(
                f"remote_hsmd_socket binary not found next to vlsd at {self.remote_socket}"
            )

        TailableProc.__init__(self, self.datadir, verbose=True)
        # Set ALLOWLIST on the signer's proc env instead of os.environ so
        # multiple signers can coexist without the test coordinator leaking
        # state between them.
        self.env["ALLOWLIST"] = env(
            "REMOTE_SIGNER_ALLOWLIST",
            "contrib/remote_hsmd/TESTING_ALLOWLIST",
        )
        self.env["VLS_AUTOAPPROVE"] = env("VLS_AUTO_APPROVE", "1")
        self.opts = [
            f"--network={network}",
            f"--datadir={self.datadir}",
            f"--connect=http://localhost:{self.port}",
            f"--rpc-server-port={self.rpc_port}",
            f"--rpc-user=bitcoind",
            f"--rpc-pass=bitcoind"
        ]
        self.prefix = "vlsd-%d" % node_id

    @property
    def cmd_line(self):
        return [self.executable] + self.opts

    def start(self, stdin=None, stdout_redir=True, stderr_redir=True):
        TailableProc.start(self, stdin, stdout_redir, stderr_redir)
        self.wait_for_log("vlsd git_desc")
        logging.info("vlsd started")

    def stop(self, timeout=10):
        logging.info("stopping vlsd")
        rc = TailableProc.stop(self, timeout)
        logging.info("vlsd stopped")
        self.logs_catchup()
        return rc

    def __del__(self):
        # __init__ may have raised before TailableProc finished setup.
        if hasattr(self, "stdout_read"):
            self.logs_catchup()
