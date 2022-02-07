from fixtures import *  # noqa: F401,F403
from pathlib import Path
from pyln.testing.utils import env, TEST_NETWORK
import subprocess
import pytest


# Skip the entire module if we don't have Rust. The same is true for
# VALGRIND, since it sometimes causes false positives in
# `std::sync::Once`
pytestmark = [
    pytest.mark.skipif(
        env('RUST') != '1',
        reason='RUST is not enabled skipping rust-dependent tests'
    ),
    pytest.mark.skipif(
        env('VALGRIND') == '1',
        reason='VALGRIND is enabled skipping rust-dependent tests, as they may report false positives.'
    ),
]


def test_rpc_client(node_factory):
    l1 = node_factory.get_node()
    bin_path = Path.cwd() / "target" / "debug" / "examples" / "cln-rpc-getinfo"
    rpc_path = Path(l1.daemon.lightning_dir) / TEST_NETWORK / "lightning-rpc"
    out = subprocess.check_output([bin_path, rpc_path], stderr=subprocess.STDOUT)
    assert(b'0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518' in out)


def test_plugin_start(node_factory):
    """Start a minimal plugin and ensure it is well-behaved
    """
    bin_path = Path.cwd() / "target" / "debug" / "examples" / "cln-plugin-startup"
    l1 = node_factory.get_node(options={"plugin": str(bin_path), 'test-option': 31337})

    cfg = l1.rpc.listconfigs()
    p = cfg['plugins'][0]
    p['path'] = None  # The path is host-specific, so blank it.
    expected = {
        'name': 'cln-plugin-startup',
        'options': {
            'test-option': 31337
        },
        'path': None
    }
    assert expected == p
