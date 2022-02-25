from fixtures import *  # noqa: F401,F403
from pathlib import Path
from pyln.testing.utils import env, TEST_NETWORK
import subprocess
import pytest


# Skip the entire module if we don't have Rust.
pytestmark = pytest.mark.skipif(
    env('RUST') != '1',
    reason='RUST is not enabled skipping rust-dependent tests'
)


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
    l2 = node_factory.get_node()

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

    # Now check that the `testmethod was registered ok
    l1.rpc.help("testmethod") == {
        'help': [
            {
                'command': 'testmethod ',
                'category': 'plugin',
                'description': 'This is a test',
                'verbose': 'This is a test'
            }
        ],
        'format-hint': 'simple'
    }

    assert l1.rpc.testmethod() == "Hello"

    l1.connect(l2)
    l1.daemon.wait_for_log(r'Got a connect hook call')
    l1.daemon.wait_for_log(r'Got a connect notification')
