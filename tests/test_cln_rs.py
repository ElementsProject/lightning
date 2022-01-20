from fixtures import *  # noqa: F401,F403
from node_pb2_grpc import NodeStub
from pathlib import Path
from pyln.testing.utils import env, TEST_NETWORK
import grpc
import node_pb2 as nodepb
import pytest
import subprocess

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

    # The plugin should be in the list of active plugins
    plugins = l1.rpc.plugin('list')['plugins']
    assert len([p for p in plugins if 'cln-plugin-startup' in p['name'] and p['active']]) == 1

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


def test_grpc_connect(node_factory):
    """Attempts to connect to the grpc interface and call getinfo"""
    bin_path = Path.cwd() / "target" / "debug" / "grpc-plugin"
    l1 = node_factory.get_node(options={"plugin": str(bin_path)})

    p = Path(l1.daemon.lightning_dir) / TEST_NETWORK
    cert_path = p / "client.pem"
    key_path = p / "client-key.pem"
    ca_cert_path = p / "ca.pem"
    creds = grpc.ssl_channel_credentials(
        root_certificates=ca_cert_path.open('rb').read(),
        private_key=key_path.open('rb').read(),
        certificate_chain=cert_path.open('rb').read()
    )

    channel = grpc.secure_channel(
        "localhost:50051",
        creds,
        options=(('grpc.ssl_target_name_override', 'cln'),)
    )
    stub = NodeStub(channel)

    response = stub.Getinfo(nodepb.GetinfoRequest())
    print(response)

    response = stub.ListFunds(nodepb.ListfundsRequest())
    print(response)


def test_grpc_generate_certificate(node_factory):
    """Test whether we correctly generate the certificates.

     - If we have no certs, we need to generate them all
     - If we have certs, we they should just get loaded
     - If we delete one cert or its key it should get regenerated.
    """
    bin_path = Path.cwd() / "target" / "debug" / "grpc-plugin"
    l1 = node_factory.get_node(options={
        "plugin": str(bin_path),
    }, start=False)

    p = Path(l1.daemon.lightning_dir) / TEST_NETWORK
    files = [p / f for f in ['ca.pem', 'ca-key.pem', 'client.pem', 'client-key.pem', 'server-key.pem', 'server.pem']]

    # Before starting no files exist.
    assert [f.exists() for f in files] == [False] * len(files)

    l1.start()
    assert [f.exists() for f in files] == [True] * len(files)

    # The files exist, restarting should not change them
    contents = [f.open().read() for f in files]
    l1.restart()
    assert contents == [f.open().read() for f in files]

    # Now we delete the last file, we should regenerate it as well as its key
    files[-1].unlink()
    l1.restart()
    assert contents[-2] != files[-2].open().read()
    assert contents[-1] != files[-1].open().read()
