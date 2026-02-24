from pyln.testing.utils import TailableProc, env
import logging
import os

class ValidatingLightningSignerD(TailableProc):
    def __init__(self, vlsd_dir, vlsd_port, vlsd_rpc_port, node_id, network):
        TailableProc.__init__(self, vlsd_dir, verbose=True)
        self.executable = env("REMOTE_SIGNER_CMD", 'vlsd2')
        os.environ['ALLOWLIST'] = env(
            'REMOTE_SIGNER_ALLOWLIST',
            'contrib/remote_hsmd/TESTING_ALLOWLIST')
        self.opts = [
            '--network={}'.format(network),
            '--datadir={}'.format(vlsd_dir),
            '--connect=http://localhost:{}'.format(vlsd_port),
            '--rpc-server-port={}'.format(vlsd_rpc_port),
            '--integration-test',
        ]
        self.prefix = 'vlsd2-%d' % (node_id)
        self.vlsd_port = vlsd_port

    @property
    def cmd_line(self):
        return [self.executable] + self.opts

    def start(self, stdin=None, stdout_redir=True, stderr_redir=True,
              wait_for_initialized=True):
        TailableProc.start(self, stdin, stdout_redir, stderr_redir)
        # We need to always wait for initialization
        self.wait_for_log("vlsd2 git_desc")
        logging.info("vlsd2 started")

    def stop(self, timeout=10):
        logging.info("stopping vlsd2")
        rc = TailableProc.stop(self, timeout)
        logging.info("vlsd2 stopped")
        self.logs_catchup()
        return rc

    def __del__(self):
        self.logs_catchup()

