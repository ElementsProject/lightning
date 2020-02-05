from collections import OrderedDict
from fixtures import *  # noqa: F401,F403
from flaky import flaky  # noqa: F401
from pyln.client import RpcError, Millisatoshi
from utils import (
    DEVELOPER, only_one, sync_blockheight, TIMEOUT, wait_for, TEST_NETWORK
)

import json
import os
import pytest
import re
import sqlite3
import subprocess
import time
import unittest


def test_option_passthrough(node_factory, directory):
    """ Ensure that registering options works.

    First attempts without the plugin and then with the plugin.
    """
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')

    help_out = subprocess.check_output([
        'lightningd/lightningd',
        '--lightning-dir={}'.format(directory),
        '--help'
    ]).decode('utf-8')
    assert('--greeting' not in help_out)

    help_out = subprocess.check_output([
        'lightningd/lightningd',
        '--lightning-dir={}'.format(directory),
        '--plugin={}'.format(plugin_path),
        '--help'
    ]).decode('utf-8')
    assert('--greeting' in help_out)

    # Now try to see if it gets accepted, would fail to start if the
    # option didn't exist
    n = node_factory.get_node(options={'plugin': plugin_path, 'greeting': 'Ciao'})
    n.stop()


def test_millisatoshi_passthrough(node_factory):
    """ Ensure that Millisatoshi arguments and return work.
    """
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/millisatoshis.py')
    n = node_factory.get_node(options={'plugin': plugin_path, 'log-level': 'io'})

    # By keyword
    ret = n.rpc.call('echo', {'msat': Millisatoshi(17), 'not_an_msat': '22msat'})['echo_msat']
    assert type(ret) == Millisatoshi
    assert ret == Millisatoshi(17)

    # By position
    ret = n.rpc.call('echo', [Millisatoshi(18), '22msat'])['echo_msat']
    assert type(ret) == Millisatoshi
    assert ret == Millisatoshi(18)


def test_rpc_passthrough(node_factory):
    """Starting with a plugin exposes its RPC methods.

    First check that the RPC method appears in the help output and
    then try to call it.

    """
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')
    n = node_factory.get_node(options={'plugin': plugin_path, 'greeting': 'Ciao'})

    # Make sure that the 'hello' command that the helloworld.py plugin
    # has registered is available.
    cmd = [hlp for hlp in n.rpc.help()['help'] if 'hello' in hlp['command']]
    assert(len(cmd) == 1)

    # Make sure usage message is present.
    assert only_one(n.rpc.help('hello')['help'])['command'] == 'hello [name]'
    # While we're at it, let's check that helloworld.py is logging
    # correctly via the notifications plugin->lightningd
    assert n.daemon.is_in_log('Plugin helloworld.py initialized')

    # Now try to call it and see what it returns:
    greet = n.rpc.hello(name='World')
    assert(greet == "Ciao World")
    with pytest.raises(RpcError):
        n.rpc.fail()


def test_plugin_dir(node_factory):
    """--plugin-dir works"""
    plugin_dir = os.path.join(os.getcwd(), 'contrib/plugins')
    node_factory.get_node(options={'plugin-dir': plugin_dir, 'greeting': 'Mars'})


def test_plugin_slowinit(node_factory):
    """Tests that the 'plugin' RPC command times out if plugin doesnt respond"""
    n = node_factory.get_node()

    with pytest.raises(RpcError, match="Timed out while waiting for plugin response"):
        n.rpc.plugin_start(os.path.join(os.getcwd(), "tests/plugins/slow_init.py"))

    # It's not actually configured yet, see what happens;
    # make sure 'rescan' and 'list' controls dont crash
    n.rpc.plugin_rescan()
    n.rpc.plugin_list()


def test_plugin_command(node_factory):
    """Tests the 'plugin' RPC command"""
    n = node_factory.get_node()

    # Make sure that the 'hello' command from the helloworld.py plugin
    # is not available.
    cmd = [hlp for hlp in n.rpc.help()["help"] if "hello" in hlp["command"]]
    assert(len(cmd) == 0)

    # Add the 'contrib/plugins' test dir
    n.rpc.plugin_startdir(directory=os.path.join(os.getcwd(), "contrib/plugins"))
    # Make sure that the 'hello' command from the helloworld.py plugin
    # is now available.
    cmd = [hlp for hlp in n.rpc.help()["help"] if "hello" in hlp["command"]]
    assert(len(cmd) == 1)

    # Make sure 'rescan' and 'list' subcommands dont crash
    n.rpc.plugin_rescan()
    n.rpc.plugin_list()

    # Make sure the plugin behaves normally after stop and restart
    assert("Successfully stopped helloworld.py."
           == n.rpc.plugin_stop(plugin="helloworld.py")["result"])
    n.daemon.wait_for_log(r"Killing plugin: helloworld.py")
    n.rpc.plugin_start(plugin=os.path.join(os.getcwd(), "contrib/plugins/helloworld.py"))
    n.daemon.wait_for_log(r"Plugin helloworld.py initialized")
    assert("Hello world" == n.rpc.call(method="hello"))

    # Now stop the helloworld plugin
    assert("Successfully stopped helloworld.py."
           == n.rpc.plugin_stop(plugin="helloworld.py")["result"])
    n.daemon.wait_for_log(r"Killing plugin: helloworld.py")
    # Make sure that the 'hello' command from the helloworld.py plugin
    # is not available anymore.
    cmd = [hlp for hlp in n.rpc.help()["help"] if "hello" in hlp["command"]]
    assert(len(cmd) == 0)

    # Test that we cannot start a plugin with 'dynamic' set to False in
    # getmanifest
    with pytest.raises(RpcError, match=r"Not a dynamic plugin"):
        n.rpc.plugin_start(plugin=os.path.join(os.getcwd(), "tests/plugins/static.py"))

    # Test that we cannot stop a started plugin with 'dynamic' flag set to
    # False
    n2 = node_factory.get_node(options={
        "plugin": os.path.join(os.getcwd(), "tests/plugins/static.py")
    })
    with pytest.raises(RpcError, match=r"static.py cannot be managed when lightningd is up"):
        n2.rpc.plugin_stop(plugin="static.py")

    # Test that we don't crash when starting a broken plugin
    with pytest.raises(RpcError, match=r"Timed out while waiting for plugin response"):
        n2.rpc.plugin_start(plugin=os.path.join(os.getcwd(), "tests/plugins/broken.py"))


def test_plugin_disable(node_factory):
    """--disable-plugin works"""
    plugin_dir = os.path.join(os.getcwd(), 'contrib/plugins')
    # We need plugin-dir before disable-plugin!
    n = node_factory.get_node(options=OrderedDict([('plugin-dir', plugin_dir),
                                                   ('disable-plugin',
                                                    '{}/helloworld.py'
                                                    .format(plugin_dir))]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')

    # Also works by basename.
    n = node_factory.get_node(options=OrderedDict([('plugin-dir', plugin_dir),
                                                   ('disable-plugin',
                                                    'helloworld.py')]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')


def test_plugin_hook(node_factory, executor):
    """The helloworld plugin registers a htlc_accepted hook.

    The hook will sleep for a few seconds and log a
    message. `lightningd` should wait for the response and only then
    complete the payment.

    """
    l1, l2 = node_factory.line_graph(2, opts={'plugin': os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')})
    start_time = time.time()
    f = executor.submit(l1.pay, l2, 100000)
    l2.daemon.wait_for_log(r'on_htlc_accepted called')

    # The hook will sleep for 20 seconds before answering, so `f`
    # should take at least that long.
    f.result()
    end_time = time.time()
    assert(end_time >= start_time + 20)


def test_plugin_connect_notifications(node_factory):
    """ test 'connect' and 'disconnect' notifications
    """
    l1, l2 = node_factory.get_nodes(2, opts={'plugin': os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')})

    l1.connect(l2)
    l1.daemon.wait_for_log(r'Received connect event')
    l2.daemon.wait_for_log(r'Received connect event')

    l2.rpc.disconnect(l1.info['id'])
    l1.daemon.wait_for_log(r'Received disconnect event')
    l2.daemon.wait_for_log(r'Received disconnect event')


def test_failing_plugins(directory):
    fail_plugins = [
        os.path.join(os.getcwd(), 'contrib/plugins/fail/failtimeout.py'),
        os.path.join(os.getcwd(), 'contrib/plugins/fail/doesnotexist.py'),
    ]

    for p in fail_plugins:
        with pytest.raises(subprocess.CalledProcessError):
            subprocess.check_output([
                'lightningd/lightningd',
                '--lightning-dir={}'.format(directory),
                '--plugin={}'.format(p),
                '--help',
            ])


def test_pay_plugin(node_factory):
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(123000, 'label', 'description', 3700)

    res = l1.rpc.pay(bolt11=inv['bolt11'])
    assert res['status'] == 'complete'

    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.call('pay')

    # Make sure usage messages are present.
    msg = 'pay bolt11 [msatoshi] [label] [riskfactor] [maxfeepercent] '\
          '[retry_for] [maxdelay] [exemptfee]'
    if DEVELOPER:
        msg += ' [use_shadow]'
    assert only_one(l1.rpc.help('pay')['help'])['command'] == msg


def test_plugin_connected_hook(node_factory):
    """ l1 uses the reject plugin to reject connections.

    l1 is configured to accept connections from l2, but not from l3.
    """
    opts = [{'plugin': os.path.join(os.getcwd(), 'tests/plugins/reject.py')}, {}, {}]
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    l1.rpc.reject(l3.info['id'])

    l2.connect(l1)
    l1.daemon.wait_for_log(r"{} is allowed".format(l2.info['id']))
    assert len(l1.rpc.listpeers(l2.info['id'])['peers']) == 1

    l3.connect(l1)
    l1.daemon.wait_for_log(r"{} is in reject list".format(l3.info['id']))

    # FIXME: this error occurs *after* connection, so we connect then drop.
    l3.daemon.wait_for_log(r"openingd-chan#1: peer_in WIRE_ERROR")
    l3.daemon.wait_for_log(r"You are in reject list")

    def check_disconnect():
        peers = l1.rpc.listpeers(l3.info['id'])['peers']
        return peers == [] or not peers[0]['connected']

    wait_for(check_disconnect)


def test_async_rpcmethod(node_factory, executor):
    """This tests the async rpcmethods.

    It works in conjunction with the `asynctest` plugin which stashes
    requests and then resolves all of them on the fifth call.
    """
    l1 = node_factory.get_node(options={'plugin': os.path.join(os.getcwd(), 'tests/plugins/asynctest.py')})

    results = []
    for i in range(10):
        results.append(executor.submit(l1.rpc.asyncqueue))

    time.sleep(3)

    # None of these should have returned yet
    assert len([r for r in results if r.done()]) == 0

    # This last one triggers the release and all results should be 42,
    # since the last number is returned for all
    l1.rpc.asyncflush(42)

    assert [r.result() for r in results] == [42] * len(results)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Only sqlite3 implements the db_write_hook currently")
def test_db_hook(node_factory, executor):
    """This tests the db hook."""
    dbfile = os.path.join(node_factory.directory, "dblog.sqlite3")
    l1 = node_factory.get_node(options={'plugin': os.path.join(os.getcwd(), 'tests/plugins/dblog.py'),
                                        'dblog-file': dbfile})

    # It should see the db being created, and sometime later actually get
    # initted.
    # This precedes startup, so needle already past
    assert l1.daemon.is_in_log(r'plugin-dblog.py: deferring \d+ commands')
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log('plugin-dblog.py: replaying pre-init data:')
    l1.daemon.wait_for_log('plugin-dblog.py: CREATE TABLE version \\(version INTEGER\\)')
    l1.daemon.wait_for_log("plugin-dblog.py: initialized.* 'startup': True")

    l1.stop()

    # Databases should be identical.
    db1 = sqlite3.connect(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'lightningd.sqlite3'))
    db2 = sqlite3.connect(dbfile)

    assert [x for x in db1.iterdump()] == [x for x in db2.iterdump()]


def test_utf8_passthrough(node_factory, executor):
    l1 = node_factory.get_node(options={'plugin': os.path.join(os.getcwd(), 'tests/plugins/utf8.py'),
                                        'log-level': 'io'})

    # This works because Python unmangles.
    res = l1.rpc.call('utf8', ['ナンセンス 1杯'])
    assert '\\u' not in res['utf8']
    assert res['utf8'] == 'ナンセンス 1杯'

    # Now, try native.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'utf8', 'ナンセンス 1杯']).decode('utf-8')
    assert '\\u' not in out
    assert out == '{\n   "utf8": "ナンセンス 1杯"\n}\n'


def test_invoice_payment_hook(node_factory):
    """ l1 uses the reject-payment plugin to reject invoices with odd preimages.
    """
    opts = [{}, {'plugin': os.path.join(os.getcwd(), 'tests/plugins/reject_some_invoices.py')}]
    l1, l2 = node_factory.line_graph(2, opts=opts)

    # This one works
    inv1 = l2.rpc.invoice(123000, 'label', 'description', preimage='1' * 64)
    l1.rpc.pay(inv1['bolt11'])

    l2.daemon.wait_for_log('label=label')
    l2.daemon.wait_for_log('msat=')
    l2.daemon.wait_for_log('preimage=' + '1' * 64)

    # This one will be rejected.
    inv2 = l2.rpc.invoice(123000, 'label2', 'description', preimage='0' * 64)
    with pytest.raises(RpcError):
        l1.rpc.pay(inv2['bolt11'])

    pstatus = l1.rpc.call('paystatus', [inv2['bolt11']])['pay'][0]
    assert pstatus['attempts'][0]['failure']['data']['failcodename'] == 'WIRE_TEMPORARY_NODE_FAILURE'

    l2.daemon.wait_for_log('label=label2')
    l2.daemon.wait_for_log('msat=')
    l2.daemon.wait_for_log('preimage=' + '0' * 64)


def test_invoice_payment_hook_hold(node_factory):
    """ l1 uses the hold_invoice plugin to delay invoice payment.
    """
    opts = [{}, {'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': TIMEOUT / 2}]
    l1, l2 = node_factory.line_graph(2, opts=opts)

    inv1 = l2.rpc.invoice(123000, 'label', 'description', preimage='1' * 64)
    l1.rpc.pay(inv1['bolt11'])


def test_openchannel_hook(node_factory, bitcoind):
    """ l2 uses the reject_odd_funding_amounts plugin to reject some openings.
    """
    opts = [{}, {'plugin': os.path.join(os.getcwd(), 'tests/plugins/reject_odd_funding_amounts.py')}]
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)

    # Get some funds.
    addr = l1.rpc.newaddr()['bech32']
    txid = bitcoind.rpc.sendtoaddress(addr, 10)
    numfunds = len(l1.rpc.listfunds()['outputs'])
    bitcoind.generate_block(1, txid)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > numfunds)

    # Even amount: works.
    l1.rpc.fundchannel(l2.info['id'], 100000)

    # Make sure plugin got all the vars we expect
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: 11 VARS')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: channel_flags=1')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: channel_reserve_satoshis=1000000msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: dust_limit_satoshis=546000msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: feerate_per_kw=7500')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: funding_satoshis=100000000msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: htlc_minimum_msat=0msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: id={}'.format(l1.info['id']))
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: max_accepted_htlcs=483')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: max_htlc_value_in_flight_msat=18446744073709551615msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: push_msat=0msat')
    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: to_self_delay=5')

    # Close it.
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(1, txid)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels']] == ['ONCHAIN'])

    # Odd amount: fails
    l1.connect(l2)
    with pytest.raises(RpcError, match=r"I don't like odd amounts"):
        l1.rpc.fundchannel(l2.info['id'], 100001)


@unittest.skipIf(not DEVELOPER, "without DEVELOPER=1, gossip v slow")
def test_htlc_accepted_hook_fail(node_factory):
    """Send payments from l1 to l2, but l2 just declines everything.

    l2 is configured with a plugin that'll hook into htlc_accepted and
    always return failures. The same should also work for forwarded
    htlcs in the second half.

    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {'plugin': os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')},
        {}
    ], wait_for_announce=True)

    # This must fail
    phash = l2.rpc.invoice(1000, "lbl", "desc")['payment_hash']
    route = l1.rpc.getroute(l2.info['id'], 1000, 1)['route']

    # Here shouldn't use `pay` command because l2 rejects with WIRE_TEMPORARY_NODE_FAILURE,
    # then it will be excluded when l1 try another pay attempt.
    # Note if the destination is excluded, the route result is undefined.
    l1.rpc.sendpay(route, phash)
    with pytest.raises(RpcError) as excinfo:
        l1.rpc.waitsendpay(phash)
    assert excinfo.value.error['data']['failcode'] == 0x2002
    assert excinfo.value.error['data']['erring_index'] == 1

    # And the invoice must still be unpaid
    inv = l2.rpc.listinvoices("lbl")['invoices']
    assert len(inv) == 1 and inv[0]['status'] == 'unpaid'

    # Now try with forwarded HTLCs: l2 should still fail them
    # This must fail
    inv = l3.rpc.invoice(1000, "lbl", "desc")['bolt11']
    with pytest.raises(RpcError):
        l1.rpc.pay(inv)

    # And the invoice must still be unpaid
    inv = l3.rpc.listinvoices("lbl")['invoices']
    assert len(inv) == 1 and inv[0]['status'] == 'unpaid'


@unittest.skipIf(not DEVELOPER, "without DEVELOPER=1, gossip v slow")
def test_htlc_accepted_hook_resolve(node_factory):
    """l3 creates an invoice, l2 knows the preimage and will shortcircuit.
    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {'plugin': os.path.join(os.getcwd(), 'tests/plugins/shortcircuit.py')},
        {}
    ], wait_for_announce=True)

    inv = l3.rpc.invoice(msatoshi=1000, label="lbl", description="desc", preimage="00" * 32)['bolt11']
    l1.rpc.pay(inv)

    # And the invoice must still be unpaid
    inv = l3.rpc.listinvoices("lbl")['invoices']
    assert len(inv) == 1 and inv[0]['status'] == 'unpaid'


def test_htlc_accepted_hook_direct_restart(node_factory, executor):
    """l2 restarts while it is pondering what to do with an HTLC.
    """
    l1, l2 = node_factory.line_graph(2, opts=[
        {'may_reconnect': True},
        {'may_reconnect': True,
         'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py')}
    ])

    i1 = l2.rpc.invoice(msatoshi=1000, label="direct", description="desc")['bolt11']
    f1 = executor.submit(l1.rpc.pay, i1)

    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')
    needle = l2.daemon.logsearch_start
    l2.restart()

    # Now it should try again, *after* initializing.
    # This may be before "Server started with public key" swallowed by restart()
    l2.daemon.logsearch_start = needle + 1
    l2.daemon.wait_for_log(r'hold_htlcs.py initializing')
    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')
    f1.result()


@unittest.skipIf(not DEVELOPER, "without DEVELOPER=1, gossip v slow")
def test_htlc_accepted_hook_forward_restart(node_factory, executor):
    """l2 restarts while it is pondering what to do with an HTLC.
    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {'may_reconnect': True},
        {'may_reconnect': True,
         'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py')},
        {'may_reconnect': True},
    ], wait_for_announce=True)

    i1 = l3.rpc.invoice(msatoshi=1000, label="direct", description="desc")['bolt11']
    f1 = executor.submit(l1.rpc.dev_pay, i1, use_shadow=False)

    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')

    needle = l2.daemon.logsearch_start
    l2.restart()

    # Now it should try again, *after* initializing.
    # This may be before "Server started with public key" swallowed by restart()
    l2.daemon.logsearch_start = needle + 1
    l2.daemon.wait_for_log(r'hold_htlcs.py initializing')
    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')

    # Grab the file where the plugin wrote the onion and read it in for some
    # additional checks
    logline = l2.daemon.wait_for_log(r'Onion written to')
    fname = re.search(r'Onion written to (.*\.json)', logline).group(1)
    onion = json.load(open(fname))
    assert onion['type'] == 'tlv'
    assert re.match(r'^11020203e80401..0608................$', onion['payload'])
    assert len(onion['shared_secret']) == 64
    assert onion['forward_amount'] == '1000msat'
    assert len(onion['next_onion']) == 2 * (1300 + 32 + 33 + 1)

    f1.result()


def test_warning_notification(node_factory):
    """ test 'warning' notifications
    """
    l1 = node_factory.get_node(options={'plugin': os.path.join(os.getcwd(), 'tests/plugins/pretend_badlog.py')}, allow_broken_log=True)

    # 1. test 'warn' level
    event = "Test warning notification(for unusual event)"
    l1.rpc.call('pretendbad', {'event': event, 'level': 'warn'})

    # ensure an unusual log_entry was produced by 'pretendunusual' method
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: Test warning notification\\(for unusual event\\)')

    # now wait for notification
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: Received warning')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: level: warn')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: time: *')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: source: plugin-pretend_badlog.py')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: log: Test warning notification\\(for unusual event\\)')

    # 2. test 'error' level, steps like above
    event = "Test warning notification(for broken event)"
    l1.rpc.call('pretendbad', {'event': event, 'level': 'error'})
    l1.daemon.wait_for_log(r'\*\*BROKEN\*\* plugin-pretend_badlog.py: Test warning notification\(for broken event\)')

    l1.daemon.wait_for_log('plugin-pretend_badlog.py: Received warning')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: level: error')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: time: *')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: source: plugin-pretend_badlog.py')
    l1.daemon.wait_for_log('plugin-pretend_badlog.py: log: Test warning notification\\(for broken event\\)')


@unittest.skipIf(not DEVELOPER, "needs to deactivate shadow routing")
def test_invoice_payment_notification(node_factory):
    """
    Test the 'invoice_payment' notification
    """
    opts = [{}, {"plugin": os.path.join(os.getcwd(), "contrib/plugins/helloworld.py")}]
    l1, l2 = node_factory.line_graph(2, opts=opts)

    msats = 12345
    preimage = '1' * 64
    label = "a_descriptive_label"
    inv1 = l2.rpc.invoice(msats, label, 'description', preimage=preimage)
    l1.rpc.dev_pay(inv1['bolt11'], use_shadow=False)

    l2.daemon.wait_for_log(r"Received invoice_payment event for label {},"
                           " preimage {}, and amount of {}msat"
                           .format(label, preimage, msats))


def test_channel_opened_notification(node_factory):
    """
    Test the 'channel_opened' notification sent at channel funding success.
    """
    opts = [{}, {"plugin": os.path.join(os.getcwd(), "tests/plugins/misc_notifications.py")}]
    amount = 10**6
    l1, l2 = node_factory.line_graph(2, fundchannel=True, fundamount=amount,
                                     opts=opts)
    l2.daemon.wait_for_log(r"A channel was opened to us by {}, "
                           "with an amount of {}*"
                           .format(l1.info["id"], amount))


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_forward_event_notification(node_factory, bitcoind, executor):
    """ test 'forward_event' notifications
    """
    amount = 10**8
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']

    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {'plugin': os.path.join(os.getcwd(), 'tests/plugins/forward_payment_status.py')},
        {}
    ], wait_for_announce=True)
    l4 = node_factory.get_node()
    l5 = node_factory.get_node(disconnect=disconnects)
    l2.openchannel(l4, 10**6, wait_for_announce=False)
    l2.openchannel(l5, 10**6, wait_for_announce=True)

    bitcoind.generate_block(5)

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 8)

    payment_hash13 = l3.rpc.invoice(amount, "first", "desc")['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    # status: offered -> settled
    l1.rpc.sendpay(route, payment_hash13)
    l1.rpc.waitsendpay(payment_hash13)

    # status: offered -> failed
    route = l1.rpc.getroute(l4.info['id'], amount, 1)['route']
    payment_hash14 = "f" * 64
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash14)
        l1.rpc.waitsendpay(payment_hash14)

    # status: offered -> local_failed
    payment_hash15 = l5.rpc.invoice(amount, 'onchain_timeout', 'desc')['payment_hash']
    fee = amount * 10 // 1000000 + 1
    c12 = l1.get_channel_scid(l2)
    c25 = l2.get_channel_scid(l5)
    route = [{'msatoshi': amount + fee - 1,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'msatoshi': amount - 1,
              'id': l5.info['id'],
              'delay': 5,
              'channel': c25}]

    executor.submit(l1.rpc.sendpay, route, payment_hash15)

    l5.daemon.wait_for_log('permfail')
    l5.wait_for_channel_onchain(l2.info['id'])
    l2.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l5.daemon.wait_for_log(' to ONCHAIN')

    l2.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US .* after 6 blocks')
    bitcoind.generate_block(6)

    l2.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                   'THEIR_UNILATERAL/OUR_HTLC')

    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
    l5.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l2])

    stats = l2.rpc.listforwards()['forwards']
    assert len(stats) == 3
    plugin_stats = l2.rpc.call('listforwards_plugin')['forwards']
    assert len(plugin_stats) == 6

    # use stats to build what we expect went to plugin.
    expect = stats[0].copy()
    # First event won't have conclusion.
    del expect['resolved_time']
    expect['status'] = 'offered'
    assert plugin_stats[0] == expect
    expect = stats[0].copy()
    assert plugin_stats[1] == expect

    expect = stats[1].copy()
    del expect['resolved_time']
    expect['status'] = 'offered'
    assert plugin_stats[2] == expect
    expect = stats[1].copy()
    assert plugin_stats[3] == expect

    expect = stats[2].copy()
    del expect['failcode']
    del expect['failreason']
    expect['status'] = 'offered'
    assert plugin_stats[4] == expect
    expect = stats[2].copy()
    assert plugin_stats[5] == expect


def test_sendpay_notifications(node_factory, bitcoind):
    """ test 'sendpay_success' and 'sendpay_failure' notifications
    """
    amount = 10**8
    opts = [{'plugin': os.path.join(os.getcwd(), 'tests/plugins/sendpay_notifications.py')},
            {},
            {'may_reconnect': False}]
    l1, l2, l3 = node_factory.line_graph(3, opts=opts, wait_for_announce=True)
    chanid23 = l2.get_channel_scid(l3)

    payment_hash1 = l3.rpc.invoice(amount, "first", "desc")['payment_hash']
    payment_hash2 = l3.rpc.invoice(amount, "second", "desc")['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l1.rpc.sendpay(route, payment_hash1)
    response1 = l1.rpc.waitsendpay(payment_hash1)

    l2.rpc.close(chanid23, 1)

    l1.rpc.sendpay(route, payment_hash2)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(payment_hash2)

    results = l1.rpc.call('listsendpays_plugin')
    assert len(results['sendpay_success']) == 1
    assert len(results['sendpay_failure']) == 1

    assert results['sendpay_success'][0] == response1
    assert results['sendpay_failure'][0] == err.value.error


def test_sendpay_notifications_nowaiter(node_factory):
    opts = [{'plugin': os.path.join(os.getcwd(), 'tests/plugins/sendpay_notifications.py')},
            {},
            {'may_reconnect': False}]
    l1, l2, l3 = node_factory.line_graph(3, opts=opts, wait_for_announce=True)
    chanid23 = l2.get_channel_scid(l3)
    amount = 10**8

    payment_hash1 = l3.rpc.invoice(amount, "first", "desc")['payment_hash']
    payment_hash2 = l3.rpc.invoice(amount, "second", "desc")['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l1.rpc.sendpay(route, payment_hash1)
    l1.daemon.wait_for_log(r'Received a sendpay_success')

    l2.rpc.close(chanid23, 1)

    l1.rpc.sendpay(route, payment_hash2)
    l1.daemon.wait_for_log(r'Received a sendpay_failure')

    results = l1.rpc.call('listsendpays_plugin')
    assert len(results['sendpay_success']) == 1
    assert len(results['sendpay_failure']) == 1


def test_rpc_command_hook(node_factory):
    """Test the `sensitive_command` hook"""
    plugin = os.path.join(os.getcwd(), "tests/plugins/rpc_command.py")
    l1 = node_factory.get_node(options={"plugin": plugin})

    # Usage of "sendpay" has been restricted by the plugin
    with pytest.raises(RpcError, match=r"You cannot do this"):
        l1.rpc.call("sendpay")

    # The plugin replaces a call made for the "invoice" command
    invoice = l1.rpc.invoice(10**6, "test_side", "test_input")
    decoded = l1.rpc.decodepay(invoice["bolt11"])
    assert decoded["description"] == "A plugin modified this description"

    # The plugin sends a custom response to "listfunds"
    funds = l1.rpc.listfunds()
    assert funds[0] == "Custom result"

    # Test command redirection to a plugin
    l1.rpc.call('help', [0])

    # Test command which removes plugin itself!
    l1.rpc.plugin_stop('rpc_command.py')


def test_libplugin(node_factory):
    """Sanity checks for plugins made with libplugin"""
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = node_factory.get_node(options={"plugin": plugin})

    # Test startup
    assert l1.daemon.is_in_log("test_libplugin initialised!")
    # Test dynamic startup
    l1.rpc.plugin_stop(plugin)
    l1.rpc.plugin_start(plugin)
    l1.rpc.check("helloworld")

    # Test commands
    assert l1.rpc.call("helloworld") == "hello world"
    assert l1.rpc.call("helloworld", {"name": "test"}) == "hello test"
    l1.stop()
    l1.daemon.opts["plugin"] = plugin
    l1.daemon.opts["name"] = "test_opt"
    l1.start()
    assert l1.rpc.call("helloworld") == "hello test_opt"
    # But param takes over!
    assert l1.rpc.call("helloworld", {"name": "test"}) == "hello test"
