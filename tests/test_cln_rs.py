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
    wait_for(lambda: node.daemon.is_in_log(r'serving grpc'))


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
    l1, l2 = node_factory.get_nodes(2, opts=[
        {"plugin": str(bin_path), 'test-option': 31337}, {}
    ])

    # The plugin should be in the list of active plugins
    plugins = l1.rpc.plugin('list')['plugins']
    assert len([p for p in plugins if 'cln-plugin-startup' in p['name'] and p['active']]) == 1

    assert str(bin_path) in l1.rpc.listconfigs()['configs']['plugin']['values_str']

    # Now check that the `testmethod was registered ok
    assert l1.rpc.help("testmethod") == {
        'help': [
            {
                'command': 'testmethod '
            }
        ],
        'format-hint': 'simple'
    }

    assert l1.rpc.testmethod() == "Hello"
    assert l1.rpc.test_custom_notification() == "Notification sent"
    l1.daemon.wait_for_log(r'Received a test_custom_notification')

    l1.connect(l2)
    l1.daemon.wait_for_log(r'Got a connect hook call')
    l1.daemon.wait_for_log(r'Got a connect notification')

    l1.rpc.setconfig("test-dynamic-option", True)
    assert l1.rpc.listconfigs("test-dynamic-option")["configs"]["test-dynamic-option"]["value_bool"]
    wait_for(lambda: l1.daemon.is_in_log(r'cln-plugin-startup: Got dynamic option change: test-dynamic-option \\"true\\"'))
    l1.rpc.setconfig("test-dynamic-option", False)
    assert not l1.rpc.listconfigs("test-dynamic-option")["configs"]["test-dynamic-option"]["value_bool"]
    wait_for(lambda: l1.daemon.is_in_log(r'cln-plugin-startup: Got dynamic option change: test-dynamic-option \\"false\\"'))


def test_plugin_options_handle_defaults(node_factory):
    """Start a minimal plugin and ensure it is well-behaved
    """
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-plugin-startup"
    l1 = node_factory.get_node(
        options={
            "plugin": str(bin_path),
            "opt-option": 31337,
            "test-option": 31338,
            "multi-str-option": ["String1", "String2"],
            "multi-str-option-default": ["NotDefault1", "NotDefault2"],
            "multi-i64-option": [1, 2, 3, 4],
            "multi-i64-option-default": [5, 6],
        }
    )
    opts = l1.rpc.testoptions()
    assert opts["opt-option"] == 31337
    assert opts["test-option"] == 31338
    assert opts["multi-str-option"] == ["String1", "String2"]
    assert opts["multi-str-option-default"] == ["NotDefault1", "NotDefault2"]
    assert opts["multi-i64-option"] == [1, 2, 3, 4]
    assert opts["multi-i64-option-default"] == [5, 6]

    # Do not set any value, should be None now
    l1 = node_factory.get_node(options={"plugin": str(bin_path)})
    opts = l1.rpc.testoptions()
    assert opts["opt-option"] is None, "opt-option has no default"
    assert opts["test-option"] == 42, "test-option has a default of 42"
    assert opts["multi-str-option"] is None
    assert opts["multi-str-option-default"] == ["Default1"]
    assert opts["multi-i64-option"] is None
    assert opts["multi-i64-option-default"] == [-42]


def test_grpc_connect(node_factory):
    """Attempts to connect to the grpc interface and call getinfo"""
    # These only exist if we have rust!
    l1 = node_factory.get_node()

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
        f"localhost:{l1.grpc_port}",
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
    l1 = node_factory.get_node(start=False)

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


def test_grpc_default_port_auto_starts(node_factory):
    """Ensure that we start cln-grpc on default port. Also check that certificates are generated."""
    l1 = node_factory.get_node(unused_grpc_port=False)

    grpcplugin = next((p for p in l1.rpc.plugin('list')['plugins'] if 'cln-grpc' in p['name'] and p['active']), None)
    # Check that the plugin is active
    assert grpcplugin is not None
    # Check that the plugin is listening on the default port
    assert l1.daemon.is_in_log(f'plugin-cln-grpc: Plugin logging initialized')
    # Check that the certificates are generated
    assert len([f for f in os.listdir(Path(l1.daemon.lightning_dir) / TEST_NETWORK) if re.match(r".*\.pem$", f)]) >= 6

    # Check server connection
    l1.grpc.Getinfo(clnpb.GetinfoRequest())


def test_grpc_wrong_auth(node_factory):
    """An mTLS client certificate should only be usable with its node

    We create two instances, each generates its own certs and keys,
    and then we try to cross the wires.
    """
    # These only exist if we have rust!
    l1, l2 = node_factory.get_nodes(2, opts=[{"start": False}, {"start": False}])
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
            f"localhost:{node.grpc_port}",
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
    l1, l2 = node_factory.get_nodes(2, opts=[{"plugin": str(bin_path)}, {}])
    l2.connect(l1)
    l2.fundchannel(l1)

    # Now create two invoices, and pay them both. Neither should
    # succeed, but we should queue them on the plugin.
    i1 = l1.rpc.invoice(label='lbl1', amount_msat='42sat', description='desc')['bolt11']
    i2 = l1.rpc.invoice(label='lbl2', amount_msat='31337sat', description='desc')['bolt11']

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
    l1, l2, l3 = node_factory.line_graph(
        3,
        announce_channels=True,  # Do not enforce scid-alias
    )
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [l1, l2, l3])

    chan = l2.rpc.listpeerchannels(l3.info['id'])

    routehint = clnpb.RoutehintList(hints=[
        clnpb.Routehint(hops=[
            clnpb.RouteHop(
                id=bytes.fromhex(l2.info['id']),
                scid=chan['channels'][0]['short_channel_id'],
                # Fees are defaults from CLN
                feebase=clnpb.Amount(msat=1),
                feeprop=10,
                expirydelta=18,
            )
        ])
    ])

    # FIXME: keysend needs (unannounced) channel in gossip_store
    l1.wait_local_channel_active(first_scid(l1, l2))

    # And now we send a keysend with that routehint list
    call = clnpb.KeysendRequest(
        destination=bytes.fromhex(l3.info['id']),
        amount_msat=clnpb.Amount(msat=42),
        routehints=routehint,
    )

    res = l1.grpc.KeySend(call)
    print(res)


def test_grpc_listpeerchannels(bitcoind, node_factory):
    """ Check that conversions of this rather complex type work.
    """
    l1, l2 = node_factory.line_graph(
        2,
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
    l1 = node_factory.get_node()
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


def test_rust_plugin_subscribe_wildcard(node_factory):
    """ Creates a plugin that loads the subscribe_wildcard plugin
    """
    bin_path = Path.cwd() / "target" / RUST_PROFILE / "examples" / "cln-subscribe-wildcard"
    l1 = node_factory.get_node(options={"plugin": bin_path})
    l2 = node_factory.get_node()

    l2.connect(l1)

    l1.daemon.wait_for_log("Received notification connect")


def test_grpc_block_added_notifications(node_factory, bitcoind):
    l1 = node_factory.get_node()

    # Test the block_added notification
    # Start listening to block added events over grpc
    block_added_stream = l1.grpc.SubscribeBlockAdded(clnpb.StreamBlockAddedRequest())
    bitcoind.generate_block(10)
    for block_added_event in block_added_stream:
        assert block_added_event.hash is not None
        assert block_added_event.height is not None

        # If we don't break out of the loop we'll
        # be waiting for ever
        break


def test_grpc_connect_notification(node_factory):
    l1, l2 = node_factory.get_nodes(2)

    # Test the connect notification
    connect_stream = l1.grpc.SubscribeConnect(clnpb.StreamConnectRequest())

    # FIXME: The above does not seem to be synchronous, causing a flake.  Wait
    # until it does something (and this seems to be something!)
    l1.daemon.wait_for_log('plugin-cln-grpc: received settings ACK')
    l2.connect(l1)

    for connect_event in connect_stream:
        assert connect_event.id.hex() == l2.info["id"]
        break


def test_grpc_custommsg_notification(node_factory):
    l1, l2 = node_factory.get_nodes(2)

    # Test the connect notification
    custommsg_stream = l1.grpc.SubscribeCustomMsg(clnpb.StreamCustomMsgRequest())
    l2.connect(l1)

    # Send the custom-msg to node l1
    # The payload doesn't matter.
    # It just needs to be valid hex which encodes to an odd BOLT-8 msg id
    l2.rpc.sendcustommsg(l1.info["id"], "3131313174657374")

    for custommsg in custommsg_stream:
        assert custommsg.peer_id.hex() == l2.info["id"]
        assert custommsg.payload.hex() == "3131313174657374"
        assert custommsg.payload == b"1111test"
        break
