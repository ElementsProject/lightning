from pyln.testing.utils import TailableProc, env, reserve_unused_port
import logging
import os
import json
from pathlib import Path
from enum import Enum 
from subprocess import run, PIPE
from typing import Union
import sys
import time

__VERSION__ = "0.0.1"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(stream=sys.stdout)],
)

def chunk_string(string: str, size: int):
    for i in range(0, len(string), size):
        yield string[i: i + size]


def ratelimit_output(output: str):
    sys.stdout.reconfigure(encoding='utf-8')
    for i in chunk_string(output, 1024):
        sys.stdout.write(i)
        sys.stdout.flush()
        time.sleep(0.01)


class Logger:
    """Redirect logging output to a json object or stdout as appropriate."""
    def __init__(self, capture: bool = False):
        self.json_output = {"result": [],
                            "log": []}
        self.capture = capture

    def str_esc(self, raw_string: str) -> str:
        assert isinstance(raw_string, str)
        return json.dumps(raw_string)[1:-1]

    def debug(self, to_log: str):
        assert isinstance(to_log, str) or hasattr(to_log, "__repr__")
        if logging.root.level > logging.DEBUG:
            return
        if self.capture:
            self.json_output['log'].append(self.str_esc(f"DEBUG: {to_log}"))
        else:
            logging.debug(to_log)

    def info(self, to_log: str):
        assert isinstance(to_log, str) or hasattr(to_log, "__repr__")
        if logging.root.level > logging.INFO:
            return
        if self.capture:
            self.json_output['log'].append(self.str_esc(f"INFO: {to_log}"))
        else:
            print(to_log)

    def warning(self, to_log: str):
        assert isinstance(to_log, str) or hasattr(to_log, "__repr__")
        if logging.root.level > logging.WARNING:
            return
        if self.capture:
            self.json_output['log'].append(self.str_esc(f"WARNING: {to_log}"))
        else:
            logging.warning(to_log)

    def error(self, to_log: str):
        assert isinstance(to_log, str) or hasattr(to_log, "__repr__")
        if logging.root.level > logging.ERROR:
            return
        if self.capture:
            self.json_output['log'].append(self.str_esc(f"ERROR: {to_log}"))
        else:
            logging.error(to_log)

    def add_result(self, result: Union[str, None]):
        assert json.dumps(result), "result must be json serializable"
        self.json_output["result"].append(result)

    def reply_json(self):
        """json output to stdout with accumulated result."""
        if len(log.json_output["result"]) == 1 and \
           isinstance(log.json_output["result"][0], list):
            # unpack sources output
            log.json_output["result"] = log.json_output["result"][0]
        output = json.dumps(log.json_output, indent=3) + '\n'
        ratelimit_output(output)


log = Logger()

repos = ["https://gitlab.com/lightning-signer/validating-lightning-signer.git"]


class ValidatingLightningSignerD(TailableProc):
    def __init__(self, lightning_dir, node_id, network):
        logging.info("Initializing ValidatingLightningSignerD")
        log.info(f"Cloning repository into {lightning_dir}")
        self.lightning_dir = lightning_dir
        clone = run(['git', 'clone', repos[0]], cwd=self.lightning_dir, check=True, timeout=120)
        signer_folder = repos[0].split("/")[-1].split(".git")[0]
        vlsd_dir = Path(self.lightning_dir / signer_folder).resolve()
        self.dir = vlsd_dir
        self.port = reserve_unused_port()
        self.rpc_port = reserve_unused_port()

        if clone.returncode != 0:
            log.error(f"Failed to clone repository: {clone.stderr}")
        else:
            log.info(f"Successfully cloned repository: {clone.stdout}")

        cargo = run(['cargo', 'build'], cwd=self.dir, check=True, timeout=300)
        if cargo.returncode != 0:
            log.error(f"Failed to build vlsd: {cargo.stderr}")
        else:
            log.info("Successfully built vlsd")

        TailableProc.__init__(self, self.dir, verbose=True)
        self.executable = env("REMOTE_SIGNER_CMD", Path(self.dir / "target" / "debug" / "vlsd"))
        os.environ['ALLOWLIST'] = env(
            'REMOTE_SIGNER_ALLOWLIST',
            'contrib/remote_hsmd/TESTING_ALLOWLIST')
        self.opts = [
            '--network={}'.format(network),
            '--datadir={}'.format(self.dir),
            '--connect=http://localhost:{}'.format(self.port),
            '--rpc-server-port={}'.format(self.rpc_port),
            '--integration-test',
        ]
        self.prefix = 'vlsd-%d' % (node_id)

    @property
    def cmd_line(self):
        return [self.executable] + self.opts

    def start(self, stdin=None, stdout_redir=True, stderr_redir=True,
              wait_for_initialized=True):
        TailableProc.start(self, stdin, stdout_redir, stderr_redir)
        # We need to always wait for initialization
        self.wait_for_log("vlsd git_desc")
        logging.info("vlsd started")

    def stop(self, timeout=10):
        logging.info("stopping vlsd")
        rc = TailableProc.stop(self, timeout)
        logging.info("vlsd stopped")
        self.logs_catchup()
        return rc

    def __del__(self):
        self.logs_catchup()

