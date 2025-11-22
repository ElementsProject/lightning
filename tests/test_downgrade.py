from fixtures import *  # noqa: F401,F403
from utils import (
    TIMEOUT  # noqa: F401
)

import os
import subprocess


def test_downgrade(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # From the binary:
    # ERROR_DBVERSION = 1
    # ERROR_DBFAIL = 2
    ERROR_USAGE = 3
    # ERROR_INTERNAL = 99

    # lightning-downgrade understands a subset of the options
    # to lightningd.
    downgrade_opts = []
    for o in l1.daemon.opts:
        if o in ('network', 'lightning-dir', 'conf', 'rpc-file', 'wallet'):
            if l1.daemon.opts[o] is None:
                downgrade_opts.append(f"--{o}")
            else:
                downgrade_opts.append(f"--{o}={l1.daemon.opts[o]}")

    cmd_line = ["tools/lightning-downgrade"] + downgrade_opts
    if os.getenv("VALGRIND") == "1":
        cmd_line = ['valgrind', '-q', '--error-exitcode=7'] + cmd_line

    # No downgrade on live nodes!
    retcode = subprocess.call(cmd_line, timeout=TIMEOUT)
    assert retcode == ERROR_USAGE

    l1.stop()
    subprocess.check_call(cmd_line)

    # Test with old lightningd if it's available.
    old_cln = os.getenv('PREV_LIGHTNINGD')
    if old_cln:
        current_executable = l1.daemon.executable
        l1.daemon.executable = old_cln

        l1.start()

        # It should connect to l2 no problems, make payment.
        l1.connect(l2)
        inv = l2.rpc.invoice(1000, 'test_downgrade', 'test_downgrade')
        l1.rpc.xpay(inv['bolt11'])
        l1.stop()
        l1.daemon.executable = current_executable

    # Another downgrade is a noop.
    assert subprocess.check_output(cmd_line).decode("utf8").startswith("Already compatible with ")

    # Should be able to upgrade without any trouble
    l1.daemon.opts['database-upgrade'] = True
    l1.start()
    assert l1.daemon.is_in_log("Updating database from version")

    l1.connect(l2)
    inv2 = l2.rpc.invoice(1000, 'test_downgrade2', 'test_downgrade2')
    l1.rpc.xpay(inv2['bolt11'])
