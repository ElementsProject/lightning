from ephemeral_port_reserve import reserve
from fixtures import *  # noqa: F401,F403
from pathlib import Path
from pyln import grpc as clnpb
from pyln.testing.utils import env, TEST_NETWORK, wait_for, sync_blockheight, TIMEOUT
from utils import first_scid
import grpc
import pytest
import subprocess
import os
import re

# Skip the entire module if we don't have Rust.
pytestmark = pytest.mark.skipif(
    env('RUST') != '1',
    reason='RUST is not enabled skipping rust-dependent tests'
)

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")


def wait_for_grpc_start(node):
    """This can happen before "public key" which start() swallows"""
    wait_for(lambda: node.daemon.is_in_log(r'serving grpc on 0.0.0.0:'))


def test_rpc_client(node_factory):
    l1 = node_factory.get_node()
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-rpc-getinfo"
    rpc_path = Path(l1.daemon.lightning_dir) / TEST_NETWORK / "lightning-rpc"
    out = subprocess.check_output([bin_path, rpc_path], stderr=subprocess.STDOUT)
    assert(b'0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518' in out)


def test_plugin_start(node_factory):
    """Start a minimal plugin and ensure it is well-behaved
    """
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-plugin-startup"
    l1 = node_factory.get_node(options={"plugin": str(bin_path), 'test-option': 31337})
    l2 = node_factory.get_node()

    # The plugin should be in the list of active plugins
    plugins = l1.rpc.plugin('list')['plugins']
    assert len([p for p in plugins if 'cln-plugin-startup' in p['name'] and p['active']]) == 1

    assert str(bin_path) in l1.rpc.listconfigs()['configs']['plugin']['values_str']

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


def test_plugin_optional_opts(node_factory):
    """Start a minimal plugin and ensure it is well-behaved
    """
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-plugin-startup"
    l1 = node_factory.get_node(options={"plugin": str(bin_path), 'opt-option': 31337})
    opts = l1.rpc.testoptions()
    print(opts)

    # Do not set any value, should be None now
    l1 = node_factory.get_node(options={"plugin": str(bin_path)})
    opts = l1.rpc.testoptions()
    print(opts)


def test_grpc_connect(node_factory):
    """Attempts to connect to the grpc interface and call getinfo"""
    # These only exist if we have rust!

    grpc_port = reserve()
    l1 = node_factory.get_node(options={"grpc-port": str(grpc_port)})

    p = Path(l1.daemon.lightning_dir) / TEST_NETWORK
    cert_path = p / "client.pem"
    key_path = p / "client-key.pem"
    ca_cert_path = p / "ca.pem"
    creds = grpc.ssl_channel_credentials(
        root_certificates=ca_cert_path.open('rb').read(),
        private_key=key_path.open('rb').read(),
        certificate_chain=cert_path.open('rb').read()
    )

    wait_for_grpc_start(l1)
    channel = grpc.secure_channel(
        f"localhost:{grpc_port}",
        creds,
        options=(('grpc.ssl_target_name_override', 'cln'),)
    )
    stub = clnpb.NodeStub(channel)

    response = stub.Getinfo(clnpb.GetinfoRequest())
    print(response)

    response = stub.ListFunds(clnpb.ListfundsRequest())
    print(response)

    inv = stub.Invoice(clnpb.InvoiceRequest(
        amount_msat=clnpb.AmountOrAny(any=True),
        description="hello",
        label="lbl1",
        preimage=b"\x00" * 32,
        cltv=24
    ))
    print(inv)

    rates = stub.Feerates(clnpb.FeeratesRequest(style='PERKB'))
    print(rates)

    # Test a failing RPC call, so we know that errors are returned correctly.
    with pytest.raises(Exception, match=r'Duplicate label'):
        # This request creates a label collision
        stub.Invoice(clnpb.InvoiceRequest(
            amount_msat=clnpb.AmountOrAny(amount=clnpb.Amount(msat=12345)),
            description="hello",
            label="lbl1",
        ))


def test_grpc_generate_certificate(node_factory):
    """Test whether we correctly generate the certificates.

     - If we have no certs, we need to generate them all
     - If we have certs, we they should just get loaded
     - If we delete one cert or its key it should get regenerated.
    """
    grpc_port = reserve()
    l1 = node_factory.get_node(options={
        "grpc-port": str(grpc_port),
    }, start=False)

    p = Path(l1.daemon.lightning_dir) / TEST_NETWORK
    files = [p / f for f in [
        'ca.pem',
        'ca-key.pem',
        'client.pem',
        'client-key.pem',
        'server-key.pem',
        'server.pem',
    ]]

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

    keys = [f for f in files if f.name.endswith('-key.pem')]
    modes = [f.stat().st_mode for f in keys]
    private = [m % 8 == 0 and (m // 8) % 8 == 0 for m in modes]
    assert all(private)


def test_grpc_no_auto_start(node_factory):
    """Ensure that we do not start cln-grpc unless a port is configured.
    Also check that we do not generate certificates.
    """
    l1 = node_factory.get_node()

    wait_for(lambda: [p for p in l1.rpc.plugin('list')['plugins'] if 'cln-grpc' in p['name']] == [])
    assert l1.daemon.is_in_log(r'plugin-cln-grpc: Killing plugin: disabled itself at init')
    p = Path(l1.daemon.lightning_dir) / TEST_NETWORK
    files = os.listdir(p)
    pem_files = [f for f in files if re.match(r".*\.pem$", f)]
    assert pem_files == []


def test_grpc_wrong_auth(node_factory):
    """An mTLS client certificate should only be usable with its node

    We create two instances, each generates its own certs and keys,
    and then we try to cross the wires.
    """
    # These only exist if we have rust!

    grpc_port = reserve()
    l1, l2 = node_factory.get_nodes(2, opts={
        "start": False,
        "grpc-port": str(grpc_port),
    })
    l1.start()
    wait_for_grpc_start(l1)

    def connect(node):
        p = Path(node.daemon.lightning_dir) / TEST_NETWORK
        cert, key, ca = [f.open('rb').read() for f in [
            p / 'client.pem',
            p / 'client-key.pem',
            p / "ca.pem"]]

        creds = grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=key,
            certificate_chain=cert,
        )

        channel = grpc.secure_channel(
            f"localhost:{grpc_port}",
            creds,
            options=(('grpc.ssl_target_name_override', 'cln'),)
        )
        return clnpb.NodeStub(channel)

    stub = connect(l1)
    # This should work, it's the correct node
    stub.Getinfo(clnpb.GetinfoRequest())

    l1.stop()
    l2.start()
    wait_for_grpc_start(l2)

    # This should not work, it's a different node
    with pytest.raises(Exception, match=r'Socket closed|StatusCode.UNAVAILABLE'):
        stub.Getinfo(clnpb.GetinfoRequest())

    # Now load the correct ones and we should be good to go
    stub = connect(l2)
    stub.Getinfo(clnpb.GetinfoRequest())


def test_cln_plugin_reentrant(node_factory, executor):
    """Ensure that we continue processing events while already handling.

    We should be continuing to handle incoming events even though a
    prior event has not completed. This is important for things like
    the `htlc_accepted` hook which needs to hold on to multiple
    incoming HTLCs.

    Scenario: l1 uses an `htlc_accepted` to hold on to incoming HTLCs,
    and we release them using an RPC method.

    """
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-plugin-reentrant"
    l1 = node_factory.get_node(options={"plugin": str(bin_path)})
    l2 = node_factory.get_node()
    l2.connect(l1)
    l2.fundchannel(l1)

    # Now create two invoices, and pay them both. Neither should
    # succeed, but we should queue them on the plugin.
    i1 = l1.rpc.invoice(label='lbl1', msatoshi='42sat', description='desc')['bolt11']
    i2 = l1.rpc.invoice(label='lbl2', msatoshi='31337sat', description='desc')['bolt11']

    f1 = executor.submit(l2.rpc.pay, i1)
    f2 = executor.submit(l2.rpc.pay, i2)

    l1.daemon.wait_for_logs(["plugin-cln-plugin-reentrant: Holding on to incoming HTLC Object"] * 2)

    print("Releasing HTLCs after holding them")
    l1.rpc.call('release')

    assert f1.result(timeout=TIMEOUT)
    assert f2.result(timeout=TIMEOUT)


def test_grpc_keysend_routehint(bitcoind, node_factory):
    """The routehints are a bit special, test that conversions work.

    3 node line graph, with l1 as the keysend sender and l3 the
    recipient.

    """
    grpc_port = reserve()
    l1, l2, l3 = node_factory.line_graph(
        3,
        opts=[
            {"grpc-port": str(grpc_port)}, {}, {}
        ],
        announce_channels=True,  # Do not enforce scid-alias
    )
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [l1, l2, l3])

    stub = l1.grpc
    chan = l2.rpc.listpeerchannels(l3.info['id'])

    routehint = clnpb.RoutehintList(hints=[
        clnpb.Routehint(hops=[
            clnpb.RouteHop(
                id=bytes.fromhex(l2.info['id']),
                short_channel_id=chan['channels'][0]['short_channel_id'],
                # Fees are defaults from CLN
                feebase=clnpb.Amount(msat=1),
                feeprop=10,
                expirydelta=18,
            )
        ])
    ])

    # FIXME: keysend needs (unannounced) channel in gossip_store
    l1.wait_channel_active(first_scid(l1, l2))

    # And now we send a keysend with that routehint list
    call = clnpb.KeysendRequest(
        destination=bytes.fromhex(l3.info['id']),
        amount_msat=clnpb.Amount(msat=42),
        routehints=routehint,
    )

    res = stub.KeySend(call)
    print(res)


def test_grpc_listpeerchannels(bitcoind, node_factory):
    """ Check that conversions of this rather complex type work.
    """
    grpc_port = reserve()
    l1, l2 = node_factory.line_graph(
        2,
        opts=[
            {"grpc-port": str(grpc_port)}, {}
        ],
        announce_channels=True,  # Do not enforce scid-alias
    )

    stub = l1.grpc
    res = stub.ListPeerChannels(clnpb.ListpeerchannelsRequest(id=None))

    # Way too many fields to check, so just do a couple
    assert len(res.channels) == 1
    c = res.channels[0]
    assert c.peer_id.hex() == l2.info['id']
    assert c.state == 2  # CHANNELD_NORMAL

    # And since we're at it let's close the channel as well so we can
    # see it in listclosedchanenls

    res = stub.Close(clnpb.CloseRequest(id=l2.info['id']))

    bitcoind.generate_block(100, wait_for_mempool=1)
    l1.daemon.wait_for_log(r'onchaind complete, forgetting peer')

    stub.ListClosedChannels(clnpb.ListclosedchannelsRequest())


def test_grpc_decode(node_factory):
    grpc_port = reserve()
    l1 = node_factory.get_node(options={'grpc-port': str(grpc_port)})
    inv = l1.grpc.Invoice(clnpb.InvoiceRequest(
        amount_msat=clnpb.AmountOrAny(any=True),
        description="desc",
        label="label",
    ))

    res = l1.grpc.DecodePay(clnpb.DecodepayRequest(
        bolt11=inv.bolt11
    ))
    # If we get here we're good, conversions work
    print(res)

    res = l1.grpc.Decode(clnpb.DecodeRequest(
        string=inv.bolt11
    ))
    print(res)
