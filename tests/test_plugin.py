from collections import OrderedDict
from datetime import datetime
from fixtures import *  # noqa: F401,F403
from flaky import flaky  # noqa: F401
from hashlib import sha256
from pyln.client import RpcError, Millisatoshi
from pyln.proto import Invoice
from utils import (
    DEVELOPER, only_one, sync_blockheight, TIMEOUT, wait_for, TEST_NETWORK,
    DEPRECATED_APIS, expected_peer_features, expected_node_features,
    expected_channel_features, account_balance,
    check_coin_moves, first_channel_id, check_coin_moves_idx, EXPERIMENTAL_FEATURES
)

import ast
import json
import os
import pytest
import re
import signal
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


def test_option_types(node_factory):
    """Ensure that desired types of options are
       respected in output """

    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/options.py')
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 22,
        'bool_opt': True,
    })

    assert n.daemon.is_in_log(r"option str_opt ok <class 'str'>")
    assert n.daemon.is_in_log(r"option int_opt 22 <class 'int'>")
    assert n.daemon.is_in_log(r"option bool_opt True <class 'bool'>")
    # flag options aren't passed through if not flagged on
    assert not n.daemon.is_in_log(r"option flag_opt")
    n.stop()

    # A blank bool_opt should default to false
    n = node_factory.get_node(options={
        'plugin': plugin_path, 'str_opt': 'ok',
        'int_opt': 22,
        'bool_opt': 'true',
        'flag_opt': None,
    })

    assert n.daemon.is_in_log(r"option bool_opt True <class 'bool'>")
    assert n.daemon.is_in_log(r"option flag_opt True <class 'bool'>")
    n.stop()

    # What happens if we give it a bad bool-option?
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 22,
        'bool_opt': '!',
    }, expect_fail=True, may_fail=True)

    # the node should fail to start, and we get a stderr msg
    assert not n.daemon.running
    assert n.daemon.is_in_stderr('bool_opt: ! does not parse as type bool')

    # What happens if we give it a bad int-option?
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 'notok',
        'bool_opt': 1,
    }, may_fail=True, expect_fail=True)

    # the node should fail to start, and we get a stderr msg
    assert not n.daemon.running
    assert n.daemon.is_in_stderr('--int_opt: notok does not parse as type int')

    # Flag opts shouldn't allow any input
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 11,
        'bool_opt': 1,
        'flag_opt': True,
    }, may_fail=True, expect_fail=True)

    # the node should fail to start, and we get a stderr msg
    assert not n.daemon.running
    assert n.daemon.is_in_stderr("--flag_opt: doesn't allow an argument")

    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_optm': ['ok', 'ok2'],
        'int_optm': [11, 12, 13],
    })

    assert n.daemon.is_in_log(r"option str_optm \['ok', 'ok2'\] <class 'list'>")
    assert n.daemon.is_in_log(r"option int_optm \[11, 12, 13\] <class 'list'>")
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

    # Try to call a method without enough arguments
    with pytest.raises(RpcError, match="processing bye: missing a required"
                                       " argument"):
        n.rpc.bye()


def test_plugin_dir(node_factory):
    """--plugin-dir works"""
    plugin_dir = os.path.join(os.getcwd(), 'contrib/plugins')
    node_factory.get_node(options={'plugin-dir': plugin_dir, 'greeting': 'Mars'})


def test_plugin_slowinit(node_factory):
    """Tests that the 'plugin' RPC command times out if plugin doesnt respond"""
    os.environ['SLOWINIT_TIME'] = '61'
    n = node_factory.get_node()

    with pytest.raises(RpcError, match=': timed out before replying to init'):
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
    n.daemon.wait_for_log(r"Killing plugin: stopped by lightningd via RPC")
    n.rpc.plugin_start(plugin=os.path.join(os.getcwd(), "contrib/plugins/helloworld.py"))
    n.daemon.wait_for_log(r"Plugin helloworld.py initialized")
    assert("Hello world" == n.rpc.call(method="hello"))

    # Now stop the helloworld plugin
    assert("Successfully stopped helloworld.py."
           == n.rpc.plugin_stop(plugin="helloworld.py")["result"])
    n.daemon.wait_for_log(r"Killing plugin: stopped by lightningd via RPC")
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
    with pytest.raises(RpcError, match=r": exited before replying to getmanifest"):
        n2.rpc.plugin_start(plugin=os.path.join(os.getcwd(), "tests/plugins/broken.py"))

    with pytest.raises(RpcError, match=r': timed out before replying to getmanifest'):
        n2.rpc.plugin_start(os.path.join(os.getcwd(), 'contrib/plugins/fail/failtimeout.py'))

    # Test that we can add a directory with more than one new plugin in it.
    try:
        n.rpc.plugin_startdir(os.path.join(os.getcwd(), "contrib/plugins"))
    except RpcError:
        pass

    # Usually, it crashes after the above return.
    n.rpc.stop()


def test_plugin_disable(node_factory):
    """--disable-plugin works"""
    plugin_dir = os.path.join(os.getcwd(), 'contrib/plugins')
    # We used to need plugin-dir before disable-plugin!
    n = node_factory.get_node(options=OrderedDict([('plugin-dir', plugin_dir),
                                                   ('disable-plugin',
                                                    '{}/helloworld.py'
                                                    .format(plugin_dir))]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')

    # Also works by basename.
    n = node_factory.get_node(options=OrderedDict([('plugin-dir', plugin_dir),
                                                   ('disable-plugin',
                                                    'helloworld.py')]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')

    # Other order also works!
    n = node_factory.get_node(options=OrderedDict([('disable-plugin',
                                                    'helloworld.py'),
                                                   ('plugin-dir', plugin_dir)]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')

    # Both orders of explicit specification work.
    n = node_factory.get_node(options=OrderedDict([('disable-plugin',
                                                    'helloworld.py'),
                                                   ('plugin',
                                                    '{}/helloworld.py'
                                                    .format(plugin_dir))]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')

    # Both orders of explicit specification work.
    n = node_factory.get_node(options=OrderedDict([('plugin',
                                                    '{}/helloworld.py'
                                                    .format(plugin_dir)),
                                                   ('disable-plugin',
                                                    'helloworld.py')]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')

    # Still disabled if we load directory.
    n.rpc.plugin_startdir(directory=os.path.join(os.getcwd(), "contrib/plugins"))
    n.daemon.wait_for_log('helloworld.py: disabled via disable-plugin')

    # Check that list works
    n = node_factory.get_node(options={'disable-plugin':
                                       ['something-else.py', 'helloworld.py']})

    assert n.rpc.listconfigs()['disable-plugin'] == ['something-else.py', 'helloworld.py']


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
          '[retry_for] [maxdelay] [exemptfee] [localofferid]'
    if DEVELOPER:
        msg += ' [use_shadow]'
    assert only_one(l1.rpc.help('pay')['help'])['command'] == msg


def test_plugin_connected_hook_chaining(node_factory):
    """ l1 uses the logger_a, reject and logger_b plugin.

    l1 is configured to accept connections from l2, but not from l3.
    we check that logger_a is always called and logger_b only for l2.
    """
    opts = [{'plugin':
             [os.path.join(os.getcwd(),
                           'tests/plugins/peer_connected_logger_a.py'),
              os.path.join(os.getcwd(),
                           'tests/plugins/reject.py'),
              os.path.join(os.getcwd(),
                           'tests/plugins/peer_connected_logger_b.py')],
             'allow_warning': True},
            {},
            {'allow_warning': True}]

    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    l2id = l2.info['id']
    l3id = l3.info['id']
    l1.rpc.reject(l3.info['id'])

    l2.connect(l1)
    l1.daemon.wait_for_logs([
        f"peer_connected_logger_a {l2id}",
        f"{l2id} is allowed",
        f"peer_connected_logger_b {l2id}"
    ])
    assert len(l1.rpc.listpeers(l2id)['peers']) == 1

    l3.connect(l1)
    l1.daemon.wait_for_logs([
        f"peer_connected_logger_a {l3id}",
        f"{l3id} is in reject list"
    ])

    # FIXME: this error occurs *after* connection, so we connect then drop.
    l3.daemon.wait_for_log(r"chan#1: peer_in WIRE_WARNING")
    l3.daemon.wait_for_log(r"You are in reject list")

    def check_disconnect():
        peers = l1.rpc.listpeers(l3id)['peers']
        return peers == [] or not peers[0]['connected']

    wait_for(check_disconnect)
    assert not l3.daemon.is_in_log(f"peer_connected_logger_b {l3id}")


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


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Only sqlite3 implements the db_write_hook currently")
def test_db_hook_multiple(node_factory, executor):
    """This tests the db hook for multiple-plugin case."""
    dbfile = os.path.join(node_factory.directory, "dblog.sqlite3")
    l1 = node_factory.get_node(options={'plugin': os.path.join(os.getcwd(), 'tests/plugins/dblog.py'),
                                        'important-plugin': os.path.join(os.getcwd(), 'tests/plugins/dbdummy.py'),
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
    inv1 = l2.rpc.invoice(1230, 'label', 'description', preimage='1' * 64)
    l1.rpc.pay(inv1['bolt11'])

    l2.daemon.wait_for_log('label=label')
    l2.daemon.wait_for_log('msat=')
    l2.daemon.wait_for_log('preimage=' + '1' * 64)

    # This one will be rejected.
    inv2 = l2.rpc.invoice(1230, 'label2', 'description', preimage='0' * 64)
    with pytest.raises(RpcError):
        l1.rpc.pay(inv2['bolt11'])

    pstatus = l1.rpc.call('paystatus', [inv2['bolt11']])['pay'][0]
    assert pstatus['attempts'][-1]['failure']['data']['failcodename'] == 'WIRE_TEMPORARY_NODE_FAILURE'

    l2.daemon.wait_for_log('label=label2')
    l2.daemon.wait_for_log('msat=')
    l2.daemon.wait_for_log('preimage=' + '0' * 64)


def test_invoice_payment_hook_hold(node_factory):
    """ l1 uses the hold_invoice plugin to delay invoice payment.
    """
    opts = [{}, {'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': TIMEOUT / 2}]
    l1, l2 = node_factory.line_graph(2, opts=opts)

    inv1 = l2.rpc.invoice(1230, 'label', 'description', preimage='1' * 64)
    l1.rpc.pay(inv1['bolt11'])


def test_openchannel_hook(node_factory, bitcoind):
    """ l2 uses the reject_odd_funding_amounts plugin to reject some openings.
    """
    opts = [{}, {'plugin': os.path.join(os.getcwd(), 'tests/plugins/reject_odd_funding_amounts.py')}]
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10**6)

    # Even amount: works.
    l1.rpc.fundchannel(l2.info['id'], 100000)

    # Make sure plugin got all the vars we expect
    expected = {
        'channel_flags': '1',
        'dust_limit_satoshis': '546000msat',
        'htlc_minimum_msat': '0msat',
        'id': l1.info['id'],
        'max_accepted_htlcs': '483',
        'max_htlc_value_in_flight_msat': '18446744073709551615msat',
        'to_self_delay': '5',
    }

    if l2.config('experimental-dual-fund'):
        # openchannel2 var checks
        expected.update({
            'commitment_feerate_per_kw': '750',
            'feerate_our_max': '150000',
            'feerate_our_min': '1875',
            'funding_feerate_best': '7500',
            'funding_feerate_max': '150000',
            'funding_feerate_min': '1875',
            'locktime': '.*',
            'their_funding': '100000000msat',
        })
    else:
        expected.update({
            'channel_reserve_satoshis': '1000000msat',
            'feerate_per_kw': '7500',
            'funding_satoshis': '100000000msat',
            'push_msat': '0msat',
        })

    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: {} VARS'.format(len(expected)))
    for k, v in expected.items():
        assert l2.daemon.is_in_log('reject_odd_funding_amounts.py: {}={}'.format(k, v))

    # Close it.
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(1, txid)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels']] == ['ONCHAIN'])

    # Odd amount: fails
    l1.connect(l2)
    with pytest.raises(RpcError, match=r"I don't like odd amounts"):
        l1.rpc.fundchannel(l2.info['id'], 100001)


def test_openchannel_hook_error_handling(node_factory, bitcoind):
    """ l2 uses a plugin that should fatal() crash the node.

    This is because the plugin rejects a channel while
    also setting a close_to address which isn't allowed.
    """
    opts = {'plugin': os.path.join(os.getcwd(), 'tests/plugins/openchannel_hook_accepter.py')}
    # openchannel_reject_but_set_close_to.py')}
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options=opts,
                               expect_fail=True,
                               may_fail=True,
                               allow_broken_log=True)
    l1.connect(l2)
    l1.fundwallet(10**6)

    # next fundchannel should fail fatal() for l2
    with pytest.raises(RpcError, match=r'Owning subdaemon (openingd|dualopend) died'):
        l1.rpc.fundchannel(l2.info['id'], 100004)
    assert l2.daemon.is_in_log("BROKEN.*Plugin rejected openchannel[2]? but also set close_to")


def test_openchannel_hook_chaining(node_factory, bitcoind):
    """ l2 uses a set of plugin that all use the openchannel_hook.

    We test that chaining works by using multiple plugins in a way
    that we check for the first plugin that rejects prevents from evaluating
    further plugin responses down the chain.

    """
    opts = [{}, {'plugin': [
        os.path.join(os.path.dirname(__file__), '..', 'tests/plugins/openchannel_hook_accept.py'),
        os.path.join(os.path.dirname(__file__), '..', 'tests/plugins/openchannel_hook_accepter.py'),
        os.path.join(os.path.dirname(__file__), '..', 'tests/plugins/openchannel_hook_reject.py')
    ]}]
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10**6)

    hook_msg = "openchannel2? hook rejects and says '"
    # 100005sat fundchannel should fail fatal() for l2
    # because hook_accepter.py rejects on that amount 'for a reason'
    with pytest.raises(RpcError, match=r'They sent error channel'):
        l1.rpc.fundchannel(l2.info['id'], 100005)

    assert l2.daemon.wait_for_log(hook_msg + "reject for a reason")
    # first plugin in the chain was called
    assert l2.daemon.is_in_log("accept on principle")
    # the third plugin must now not be called anymore
    assert not l2.daemon.is_in_log("reject on principle")

    # 100000sat is good for hook_accepter, so it should fail 'on principle'
    # at third hook openchannel_reject.py
    with pytest.raises(RpcError, match=r'They sent error channel'):
        l1.rpc.fundchannel(l2.info['id'], 100000)
    assert l2.daemon.wait_for_log(hook_msg + "reject on principle")


def test_channel_state_changed_bilateral(node_factory, bitcoind):
    """ We open and close a channel and check notifications both sides.

    The misc_notifications.py plugin logs `channel_state_changed` events.
    """
    opts = {"plugin": os.path.join(os.getcwd(), "tests/plugins/misc_notifications.py")}
    l1, l2 = node_factory.line_graph(2, opts=opts)

    l1_id = l1.rpc.getinfo()["id"]
    l2_id = l2.rpc.getinfo()["id"]
    cid = l1.get_channel_id(l2)
    scid = l1.get_channel_scid(l2)

    # a helper that gives us the next channel_state_changed log entry
    def wait_for_event(node):
        msg = node.daemon.wait_for_log("channel_state_changed.*new_state.*")
        event = ast.literal_eval(re.findall(".*({.*}).*", msg)[0])
        return event

    # check channel 'opener' and 'closer' within this testcase ...
    assert(l1.rpc.listpeers()['peers'][0]['channels'][0]['opener'] == 'local')
    assert(l2.rpc.listpeers()['peers'][0]['channels'][0]['opener'] == 'remote')
    # the 'closer' should be null initially
    assert(l2.rpc.listpeers()['peers'][0]['channels'][0]['closer'] is None)
    assert(l2.rpc.listpeers()['peers'][0]['channels'][0]['closer'] is None)

    event1 = wait_for_event(l1)
    event2 = wait_for_event(l2)
    if l1.config('experimental-dual-fund'):
        # Dual funded channels have an extra state change
        assert(event1['peer_id'] == l2_id)  # we only test these IDs the first time
        assert(event1['channel_id'] == cid)
        assert(event1['short_channel_id'] is None)
        assert(event1['old_state'] == "DUALOPEND_OPEN_INIT")
        assert(event1['new_state'] == "DUALOPEND_AWAITING_LOCKIN")
        assert(event1['cause'] == "user")
        assert(event1['message'] == "Sigs exchanged, waiting for lock-in")
        event1 = wait_for_event(l1)
        assert(event2['peer_id'] == l1_id)  # we only test these IDs the first time
        assert(event2['channel_id'] == cid)
        assert(event2['short_channel_id'] is None)
        assert(event2['old_state'] == "DUALOPEND_OPEN_INIT")
        assert(event2['new_state'] == "DUALOPEND_AWAITING_LOCKIN")
        assert(event2['cause'] == "remote")
        assert(event2['message'] == "Sigs exchanged, waiting for lock-in")
        event2 = wait_for_event(l2)

    assert(event1['peer_id'] == l2_id)  # we only test these IDs the first time
    assert(event1['channel_id'] == cid)
    assert(event1['short_channel_id'] == scid)
    if l1.config('experimental-dual-fund'):
        assert(event1['old_state'] == "DUALOPEND_AWAITING_LOCKIN")
    else:
        assert(event1['old_state'] == "CHANNELD_AWAITING_LOCKIN")
    assert(event1['new_state'] == "CHANNELD_NORMAL")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Lockin complete")

    assert(event2['peer_id'] == l1_id)
    assert(event2['channel_id'] == cid)
    assert(event2['short_channel_id'] == scid)
    if l1.config('experimental-dual-fund'):
        assert(event2['old_state'] == "DUALOPEND_AWAITING_LOCKIN")
    else:
        assert(event2['old_state'] == "CHANNELD_AWAITING_LOCKIN")
    assert(event2['new_state'] == "CHANNELD_NORMAL")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Lockin complete")

    # also test the correctness of timestamps once
    assert(datetime.strptime(event1['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ'))
    assert(datetime.strptime(event2['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ'))

    # close channel and look for stateful events
    l1.rpc.close(scid)

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "CHANNELD_NORMAL")
    assert(event1['new_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "User or plugin invoked close command")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CHANNELD_NORMAL")
    assert(event2['new_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Peer closes channel")

    # 'closer' should now be set accordingly ...
    assert(l1.rpc.listpeers()['peers'][0]['channels'][0]['closer'] == 'local')
    assert(l2.rpc.listpeers()['peers'][0]['channels'][0]['closer'] == 'remote')

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event1['new_state'] == "CLOSINGD_SIGEXCHANGE")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Start closingd")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event2['new_state'] == "CLOSINGD_SIGEXCHANGE")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Start closingd")

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "CLOSINGD_SIGEXCHANGE")
    assert(event1['new_state'] == "CLOSINGD_COMPLETE")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Closing complete")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CLOSINGD_SIGEXCHANGE")
    assert(event2['new_state'] == "CLOSINGD_COMPLETE")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Closing complete")

    bitcoind.generate_block(100, wait_for_mempool=1)  # so it gets settled

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "CLOSINGD_COMPLETE")
    assert(event1['new_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Onchain funding spend")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CLOSINGD_COMPLETE")
    assert(event2['new_state'] == "FUNDING_SPEND_SEEN")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Onchain funding spend")

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['new_state'] == "ONCHAIN")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Onchain init reply")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "FUNDING_SPEND_SEEN")
    assert(event2['new_state'] == "ONCHAIN")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Onchain init reply")


def test_channel_state_changed_unilateral(node_factory, bitcoind):
    """ We open, disconnect, force-close a channel and check for notifications.

    The misc_notifications.py plugin logs `channel_state_changed` events.
    """
    # FIXME: We can get warnings from unilteral changes, since we treat
    # such errors a soft because LND.
    opts = {"plugin": os.path.join(os.getcwd(), "tests/plugins/misc_notifications.py"),
            "allow_warning": True}
    l1, l2 = node_factory.line_graph(2, opts=opts)

    l1_id = l1.rpc.getinfo()["id"]
    cid = l1.get_channel_id(l2)
    scid = l1.get_channel_scid(l2)

    # a helper that gives us the next channel_state_changed log entry
    def wait_for_event(node):
        msg = node.daemon.wait_for_log("channel_state_changed.*new_state.*")
        event = ast.literal_eval(re.findall(".*({.*}).*", msg)[0])
        return event

    event2 = wait_for_event(l2)
    if l2.config('experimental-dual-fund'):
        assert(event2['peer_id'] == l1_id)
        assert(event2['channel_id'] == cid)
        assert(event2['short_channel_id'] is None)
        assert(event2['old_state'] == "DUALOPEND_OPEN_INIT")
        assert(event2['new_state'] == "DUALOPEND_AWAITING_LOCKIN")
        assert(event2['cause'] == "remote")
        assert(event2['message'] == "Sigs exchanged, waiting for lock-in")
        event2 = wait_for_event(l2)

    assert(event2['peer_id'] == l1_id)  # we only test these IDs the first time
    assert(event2['channel_id'] == cid)
    assert(event2['short_channel_id'] == scid)
    if l2.config('experimental-dual-fund'):
        assert(event2['old_state'] == "DUALOPEND_AWAITING_LOCKIN")
    else:
        assert(event2['old_state'] == "CHANNELD_AWAITING_LOCKIN")
    assert(event2['new_state'] == "CHANNELD_NORMAL")
    assert(event2['cause'] == "remote")
    assert(event2['message'] == "Lockin complete")

    # close channel unilaterally and look for stateful events
    l1.rpc.stop()
    wait_for(lambda: not only_one(l2.rpc.listpeers()['peers'])['connected'])
    l2.rpc.close(scid, 1)  # force close after 1sec timeout

    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CHANNELD_NORMAL")
    assert(event2['new_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event2['cause'] == "user")
    assert(event2['message'] == "User or plugin invoked close command")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "CHANNELD_SHUTTING_DOWN")
    assert(event2['new_state'] == "AWAITING_UNILATERAL")
    assert(event2['cause'] == "user")
    assert(event2['message'] == "Forcibly closed by `close` command timeout")

    # restart l1 early, as the test gets flaky when done after generate_block(100)
    l1.restart()
    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 1)
    # check 'closer' on l2 while the peer is not yet forgotten
    assert(l2.rpc.listpeers()['peers'][0]['channels'][0]['closer'] == 'local')

    # settle the channel closure
    bitcoind.generate_block(100)

    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "AWAITING_UNILATERAL")
    assert(event2['new_state'] == "FUNDING_SPEND_SEEN")
    assert(event2['cause'] == "user")
    assert(event2['message'] == "Onchain funding spend")
    event2 = wait_for_event(l2)
    assert(event2['old_state'] == "FUNDING_SPEND_SEEN")
    assert(event2['new_state'] == "ONCHAIN")
    assert(event2['cause'] == "user")
    assert(event2['message'] == "Onchain init reply")

    # Check 'closer' on l1 while the peer is not yet forgotten
    event1 = wait_for_event(l1)
    assert(l1.rpc.listpeers()['peers'][0]['channels'][0]['closer'] == 'remote')

    # check if l1 sees ONCHAIN reasons for his channel
    assert(event1['old_state'] == "CHANNELD_NORMAL")
    assert(event1['new_state'] == "AWAITING_UNILATERAL")
    assert(event1['cause'] == "onchain")
    assert(event1['message'] == "Funding transaction spent")
    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "AWAITING_UNILATERAL")
    assert(event1['new_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['cause'] == "onchain")
    assert(event1['message'] == "Onchain funding spend")
    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['new_state'] == "ONCHAIN")
    assert(event1['cause'] == "onchain")
    assert(event1['message'] == "Onchain init reply")


def test_channel_state_change_history(node_factory, bitcoind):
    """ We open and close a channel and check for state_canges entries.

    """
    l1, l2 = node_factory.line_graph(2)
    scid = l1.get_channel_scid(l2)

    l1.rpc.close(scid)
    bitcoind.generate_block(100)  # so it gets settled
    bitcoind.generate_block(100)  # so it gets settled

    history = l1.rpc.listpeers()['peers'][0]['channels'][0]['state_changes']
    if l1.config('experimental-dual-fund'):
        assert(history[0]['cause'] == "user")
        assert(history[0]['old_state'] == "DUALOPEND_OPEN_INIT")
        assert(history[0]['new_state'] == "DUALOPEND_AWAITING_LOCKIN")
        assert(history[1]['cause'] == "user")
        assert(history[1]['old_state'] == "DUALOPEND_AWAITING_LOCKIN")
        assert(history[1]['new_state'] == "CHANNELD_NORMAL")
        assert(history[2]['cause'] == "user")
        assert(history[2]['new_state'] == "CHANNELD_SHUTTING_DOWN")
        assert(history[3]['cause'] == "user")
        assert(history[3]['new_state'] == "CLOSINGD_SIGEXCHANGE")
        assert(history[4]['cause'] == "user")
        assert(history[4]['new_state'] == "CLOSINGD_COMPLETE")
        assert(history[4]['message'] == "Closing complete")
    else:
        assert(history[0]['cause'] == "user")
        assert(history[0]['old_state'] == "CHANNELD_AWAITING_LOCKIN")
        assert(history[0]['new_state'] == "CHANNELD_NORMAL")
        assert(history[1]['cause'] == "user")
        assert(history[1]['new_state'] == "CHANNELD_SHUTTING_DOWN")
        assert(history[2]['cause'] == "user")
        assert(history[2]['new_state'] == "CLOSINGD_SIGEXCHANGE")
        assert(history[3]['cause'] == "user")
        assert(history[3]['new_state'] == "CLOSINGD_COMPLETE")
        assert(history[3]['message'] == "Closing complete")


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


@unittest.skipIf(not DEVELOPER, "needs to deactivate shadow routing")
def test_invoice_creation_notification(node_factory):
    """
    Test the 'invoice_creation' notification
    """
    opts = [{}, {"plugin": os.path.join(os.getcwd(), "contrib/plugins/helloworld.py")}]
    l1, l2 = node_factory.line_graph(2, opts=opts)

    msats = 12345
    preimage = '1' * 64
    label = "a_descriptive_label"
    l2.rpc.invoice(msats, label, 'description', preimage=preimage)

    l2.daemon.wait_for_log(r"Received invoice_creation event for label {},"
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

    # Might have already passed, so reset start.
    l2.daemon.logsearch_start = 0
    l2.daemon.wait_for_log(r"A channel was opened to us by {}, "
                           "with an amount of {}*"
                           .format(l1.info["id"], amount))


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_forward_event_notification(node_factory, bitcoind, executor):
    """ test 'forward_event' notifications
    """
    amount = 10**8
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']
    plugin = os.path.join(
        os.path.dirname(__file__),
        'plugins',
        'forward_payment_status.py'
    )
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts=[
        {},
        {'plugin': plugin},
        {},
        {},
        {'disconnect': disconnects}])

    l1.openchannel(l2, confirm=False, wait_for_announce=False)
    l2.openchannel(l3, confirm=False, wait_for_announce=False)
    l2.openchannel(l4, confirm=False, wait_for_announce=False)
    l2.openchannel(l5, confirm=False, wait_for_announce=False)

    # Generate 5, then make sure everyone is up to date before
    # last one, otherwise they might think it's in the future!
    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1, l2, l3, l4, l5])
    bitcoind.generate_block(1)

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
    l1 = node_factory.get_node(options={"plugin": plugin,
                                        'allow-deprecated-apis': False})

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

    # Test hooks and notifications
    l2 = node_factory.get_node()
    l2.connect(l1)
    l1.daemon.wait_for_log("{} peer_connected".format(l2.info["id"]))
    l1.daemon.wait_for_log("{} connected".format(l2.info["id"]))

    # Test RPC calls FIXME: test concurrent ones ?
    assert l1.rpc.call("testrpc") == l1.rpc.getinfo()

    # Make sure deprecated options nor commands are mentioned.
    with pytest.raises(RpcError, match=r'Command "testrpc-deprecated" is deprecated'):
        l1.rpc.call('testrpc-deprecated')

    assert not any([h['command'] == 'testrpc-deprecated'
                    for h in l1.rpc.help()['help']])
    with pytest.raises(RpcError, match=r"Deprecated command.*testrpc-deprecated"):
        l1.rpc.help('testrpc-deprecated')

    assert 'name-deprecated' not in str(l1.rpc.listconfigs())

    l1.stop()
    l1.daemon.opts["name-deprecated"] = "test_opt"

    # This actually dies while waiting for the logs.
    with pytest.raises(ValueError):
        l1.start()

    del l1.daemon.opts["name-deprecated"]
    l1.start()


def test_libplugin_deprecated(node_factory):
    """Sanity checks for plugins made with libplugin using deprecated args"""
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = node_factory.get_node(options={"plugin": plugin,
                                        'name-deprecated': 'test_opt depr',
                                        'allow-deprecated-apis': True})

    assert l1.rpc.call("helloworld") == "hello test_opt depr"
    l1.rpc.help('testrpc-deprecated')
    assert l1.rpc.call("testrpc-deprecated") == l1.rpc.getinfo()


@unittest.skipIf(
    not DEVELOPER or DEPRECATED_APIS, "needs LIGHTNINGD_DEV_LOG_IO and new API"
)
def test_plugin_feature_announce(node_factory):
    """Check that features registered by plugins show up in messages.

    l1 is the node under test, l2 only serves as the counterparty for a
    channel to check the featurebits in the `channel_announcement`. The plugin
    registers an individual featurebit for each of the locations we can stash
    feature bits in:

     - 1 << 201 for `init` messages
     - 1 << 203 for `node_announcement`
     - 1 << 205 for bolt11 invoices

    """
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/feature-test.py')
    l1, l2 = node_factory.line_graph(
        2, opts=[{'plugin': plugin, 'log-level': 'io'}, {}],
        wait_for_announce=True
    )

    extra = []
    if l1.config('experimental-dual-fund'):
        extra.append(223)

    # Check the featurebits we've set in the `init` message from
    # feature-test.py.
    assert l1.daemon.is_in_log(r'\[OUT\] 001000022200....{}'
                               .format(expected_peer_features(extra=[201] + extra)))

    # Check the invoice featurebit we set in feature-test.py
    inv = l1.rpc.invoice(123, 'lbl', 'desc')['bolt11']
    details = Invoice.decode(inv)
    assert(details.featurebits.int & (1 << 205) != 0)

    # Check the featurebit set in the `node_announcement`
    node = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['features'] == expected_node_features(extra=[203] + extra)


def test_hook_chaining(node_factory):
    """Check that hooks are called in order and the chain exits correctly

    We start two nodes, l2 will have two plugins registering the same hook
    (`htlc_accepted`) but handle different cases:

    - the `odd` plugin only handles the "AA"*32 preimage
    - the `even` plugin only handles the "BB"*32 preimage

    We check that plugins are called in the order they are registering the
    hook, and that they exit the call chain as soon as one plugin returns a
    result that isn't `continue`. On exiting the chain the remaining plugins
    are not called. If no plugin exits the chain we continue to handle
    internally as usual.

    """
    l1, l2 = node_factory.line_graph(2)

    # Start the plugins manually instead of specifying them on the command
    # line, otherwise we cannot guarantee the order in which the hooks are
    # registered.
    p1 = os.path.join(os.path.dirname(__file__), "plugins/hook-chain-odd.py")
    p2 = os.path.join(os.path.dirname(__file__), "plugins/hook-chain-even.py")
    l2.rpc.plugin_start(p1)
    l2.rpc.plugin_start(p2)

    preimage1 = b'\xAA' * 32
    preimage2 = b'\xBB' * 32
    preimage3 = b'\xCC' * 32
    hash1 = sha256(preimage1).hexdigest()
    hash2 = sha256(preimage2).hexdigest()
    hash3 = sha256(preimage3).hexdigest()

    inv = l2.rpc.invoice(123, 'odd', "Odd payment handled by the first plugin",
                         preimage="AA" * 32)['bolt11']
    l1.rpc.pay(inv)

    # The first plugin will handle this, the second one should not be called.
    assert(l2.daemon.is_in_log(
        r'plugin-hook-chain-odd.py: htlc_accepted called for payment_hash {}'.format(hash1)
    ))
    assert(not l2.daemon.is_in_log(
        r'plugin-hook-chain-even.py: htlc_accepted called for payment_hash {}'.format(hash1)
    ))

    # The second run is with a payment_hash that `hook-chain-even.py` knows
    # about. `hook-chain-odd.py` is called, it returns a `continue`, and then
    # `hook-chain-even.py` resolves it.
    inv = l2.rpc.invoice(
        123, 'even', "Even payment handled by the second plugin", preimage="BB" * 32
    )['bolt11']
    l1.rpc.pay(inv)
    assert(l2.daemon.is_in_log(
        r'plugin-hook-chain-odd.py: htlc_accepted called for payment_hash {}'.format(hash2)
    ))
    assert(l2.daemon.is_in_log(
        r'plugin-hook-chain-even.py: htlc_accepted called for payment_hash {}'.format(hash2)
    ))

    # And finally an invoice that neither know about, so it should get settled
    # by the internal invoice handling.
    inv = l2.rpc.invoice(123, 'neither', "Neither plugin handles this",
                         preimage="CC" * 32)['bolt11']
    l1.rpc.pay(inv)
    assert(l2.daemon.is_in_log(
        r'plugin-hook-chain-odd.py: htlc_accepted called for payment_hash {}'.format(hash3)
    ))
    assert(l2.daemon.is_in_log(
        r'plugin-hook-chain-even.py: htlc_accepted called for payment_hash {}'.format(hash3)
    ))


def test_bitcoin_backend(node_factory, bitcoind):
    """
    This tests interaction with the Bitcoin backend, but not specifically bcli
    """
    l1 = node_factory.get_node(start=False, options={"disable-plugin": "bcli"},
                               may_fail=True, allow_broken_log=True)

    # We don't start if we haven't all the required methods registered.
    plugin = os.path.join(os.getcwd(), "tests/plugins/bitcoin/part1.py")
    l1.daemon.opts["plugin"] = plugin
    try:
        l1.daemon.start()
    except ValueError:
        assert l1.daemon.is_in_log("Missing a Bitcoin plugin command")
        # Now we should start if all the commands are registered, even if they
        # are registered by two distincts plugins.
        del l1.daemon.opts["plugin"]
        l1.daemon.opts["plugin-dir"] = os.path.join(os.getcwd(),
                                                    "tests/plugins/bitcoin/")
        try:
            l1.daemon.start()
        except ValueError:
            msg = "All Bitcoin plugin commands registered"
            assert l1.daemon.is_in_log(msg)
        else:
            raise Exception("We registered all commands but couldn't start!")
    else:
        raise Exception("We could start without all commands registered !!")

    # But restarting with just bcli is ok
    del l1.daemon.opts["plugin-dir"]
    del l1.daemon.opts["disable-plugin"]
    l1.start()
    assert l1.daemon.is_in_log("bitcoin-cli initialized and connected to"
                               " bitcoind")


def test_bcli(node_factory, bitcoind, chainparams):
    """
    This tests the bcli plugin, used to gather Bitcoin data from a local
    bitcoind.
    Mostly sanity checks of the interface..
    """
    l1, l2 = node_factory.get_nodes(2)

    # We cant stop it dynamically
    with pytest.raises(RpcError):
        l1.rpc.plugin_stop("bcli")

    # Failure case of feerate is tested in test_misc.py
    estimates = l1.rpc.call("estimatefees")
    for est in ["opening", "mutual_close", "unilateral_close", "delayed_to_us",
                "htlc_resolution", "penalty", "min_acceptable",
                "max_acceptable"]:
        assert est in estimates

    resp = l1.rpc.call("getchaininfo")
    assert resp["chain"] == chainparams['name']
    for field in ["headercount", "blockcount", "ibd"]:
        assert field in resp

    # We shouldn't get upset if we ask for an unknown-yet block
    resp = l1.rpc.call("getrawblockbyheight", {"height": 500})
    assert resp["blockhash"] is resp["block"] is None
    resp = l1.rpc.call("getrawblockbyheight", {"height": 50})
    assert resp["blockhash"] is not None and resp["blockhash"] is not None
    # Some other bitcoind-failure cases for this call are covered in
    # tests/test_misc.py

    l1.fundwallet(10**5)
    l1.connect(l2)
    fc = l1.rpc.fundchannel(l2.info["id"], 10**4 * 3)
    txo = l1.rpc.call("getutxout", {"txid": fc['txid'], "vout": fc['outnum']})
    assert (Millisatoshi(txo["amount"]) == Millisatoshi(10**4 * 3 * 10**3)
            and txo["script"].startswith("0020"))
    l1.rpc.close(l2.info["id"])
    # When output is spent, it should give us null !
    wait_for(lambda: l1.rpc.call("getutxout", {
        "txid": fc['txid'],
        "vout": fc['outnum']
    })['amount'] is None)

    resp = l1.rpc.call("sendrawtransaction", {"tx": "dummy", "allowhighfees": False})
    assert not resp["success"] and "decode failed" in resp["errmsg"]


def test_hook_crash(node_factory, executor, bitcoind):
    """Verify that we fail over if a plugin crashes while handling a hook.

    We create a star topology, with l1 opening channels to the other nodes,
    and then triggering the plugins on those nodes in order to exercise the
    hook chain. p0 is the interesting plugin because as soon as it get called
    for the htlc_accepted hook it'll crash on purpose. We should still make it
    through the chain, the plugins should all be called and the payment should
    still go through.

    """
    p0 = os.path.join(os.path.dirname(__file__), "plugins/hook-crash.py")
    p1 = os.path.join(os.path.dirname(__file__), "plugins/hook-chain-odd.py")
    p2 = os.path.join(os.path.dirname(__file__), "plugins/hook-chain-even.py")
    perm = [
        (p0, p1, p2),  # Crashing plugin is first in chain
        (p1, p0, p2),  # Crashing plugin is in the middle of the chain
        (p1, p2, p0),  # Crashing plugin is last in chain
    ]

    l1 = node_factory.get_node()
    nodes = [node_factory.get_node() for _ in perm]

    # Start them in any order and we should still always end up with each
    # plugin being called and ultimately the `pay` call should succeed:
    for plugins, n in zip(perm, nodes):
        for p in plugins:
            n.rpc.plugin_start(p)
        l1.openchannel(n, 10**6, confirm=False, wait_for_announce=False)

    bitcoind.generate_block(6)

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2 * len(perm))

    # Start an RPC call that should error once the plugin crashes.
    f1 = executor.submit(nodes[0].rpc.hold_rpc_call)

    futures = []
    for n in nodes:
        inv = n.rpc.invoice(123, "lbl", "desc")['bolt11']
        futures.append(executor.submit(l1.rpc.pay, inv))

    for n in nodes:
        n.daemon.wait_for_logs([
            r'Plugin is about to crash.',
            r'plugin-hook-chain-odd.py: htlc_accepted called for payment_hash',
            r'plugin-hook-chain-even.py: htlc_accepted called for payment_hash',
        ])

    # Collect the results:
    [f.result(TIMEOUT) for f in futures]

    # Make sure the RPC call was terminated with the correct error
    with pytest.raises(RpcError, match=r'Plugin terminated before replying'):
        f1.result(10)


def test_feature_set(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/show_feature_set.py')
    l1 = node_factory.get_node(options={"plugin": plugin})

    fs = l1.rpc.call('getfeatureset')
    extra = [233] if l1.config('experimental-dual-fund') else []

    assert fs['init'] == expected_peer_features(extra=extra)
    assert fs['node'] == expected_node_features(extra=extra)
    assert fs['channel'] == expected_channel_features()
    assert 'invoice' in fs


def test_replacement_payload(node_factory):
    """Test that htlc_accepted plugin hook can replace payload"""
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/replace_payload.py')
    l1, l2 = node_factory.line_graph(
        2,
        opts=[{}, {"plugin": plugin}],
        wait_for_announce=True
    )

    # Replace with an invalid payload.
    l2.rpc.call('setpayload', ['0000'])
    inv = l2.rpc.invoice(123, 'test_replacement_payload', 'test_replacement_payload')['bolt11']
    with pytest.raises(RpcError, match=r"WIRE_INVALID_ONION_PAYLOAD \(reply from remote\)"):
        l1.rpc.pay(inv)

    # Replace with valid payload, but corrupt payment_secret
    l2.rpc.call('setpayload', ['corrupt_secret'])

    with pytest.raises(RpcError, match=r"WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS \(reply from remote\)"):
        l1.rpc.pay(inv)

    assert l2.daemon.wait_for_log("Attept to pay.*with wrong secret")


@unittest.skipIf(not DEVELOPER, "Requires dev_sign_last_tx")
def test_watchtower(node_factory, bitcoind, directory, chainparams):
    """Test watchtower hook.

    l1 and l2 open a channel, make a couple of updates and then l1 cheats on
    l2 while that one is offline. The watchtower plugin meanwhile stashes all
    the penalty transactions and we release the one matching the offending
    commitment transaction.

    """
    p = os.path.join(os.path.dirname(__file__), "plugins/watchtower.py")
    l1, l2 = node_factory.line_graph(
        2,
        opts=[{'may_fail': True, 'allow_broken_log': True}, {'plugin': p}]
    )

    # Force a new commitment
    l1.rpc.pay(l2.rpc.invoice(25000000, 'lbl1', 'desc1')['bolt11'])

    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    # Now make sure it is out of date
    l1.rpc.pay(l2.rpc.invoice(25000000, 'lbl2', 'desc2')['bolt11'])

    # l2 stops watching the chain, allowing the watchtower to react
    l2.stop()

    # Now l1 cheats
    bitcoind.rpc.sendrawtransaction(tx)
    time.sleep(1)
    bitcoind.generate_block(1)

    wt_file = os.path.join(
        l2.daemon.lightning_dir,
        chainparams['name'],
        'watchtower.csv'
    )

    cheat_tx = bitcoind.rpc.decoderawtransaction(tx)
    for l in open(wt_file, 'r'):
        txid, penalty = l.strip().split(', ')
        if txid == cheat_tx['txid']:
            # This one should succeed, since it is a response to the cheat_tx
            bitcoind.rpc.sendrawtransaction(penalty)
            break

    # Need this to check that l2 gets the funds
    penalty_meta = bitcoind.rpc.decoderawtransaction(penalty)

    time.sleep(1)
    bitcoind.generate_block(1)

    # Make sure l2's normal penalty_tx doesn't reach the network
    def mock_sendrawtransaction(tx):
        print("NOT broadcasting", tx)

    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)

    # Restart l2, and it should continue where the watchtower left off:
    l2.start()

    # l2 will still try to broadcast its latest commitment tx, but it'll fail
    # since l1 has cheated. All commitments share the same prefix, so look for
    # that.
    penalty_prefix = tx[:(4 + 1 + 36) * 2]  # version, txin_count, first txin in hex
    l2.daemon.wait_for_log(r'Expected error broadcasting tx {}'.format(penalty_prefix))

    # Now make sure the penalty output ends up in our wallet
    fund_txids = [o['txid'] for o in l2.rpc.listfunds()['outputs']]
    assert(penalty_meta['txid'] in fund_txids)


def test_plugin_fail(node_factory):
    """Test that a plugin which fails (not during a command)"""
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/fail_by_itself.py')
    l1 = node_factory.get_node(options={"plugin": plugin})

    time.sleep(2)
    # It should clean up!
    assert 'failcmd' not in [h['command'] for h in l1.rpc.help()['help']]
    l1.daemon.wait_for_log(r': exited during normal operation')

    l1.rpc.plugin_start(plugin)
    time.sleep(2)
    # It should clean up!
    assert 'failcmd' not in [h['command'] for h in l1.rpc.help()['help']]
    l1.daemon.wait_for_log(r': exited during normal operation')


@unittest.skipIf(not DEVELOPER, "without DEVELOPER=1, gossip v slow")
def test_coin_movement_notices(node_factory, bitcoind, chainparams):
    """Verify that coin movements are triggered correctly.
    """

    l1_l2_mvts = [
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'deposit'},
        {'type': 'channel_mvt', 'credit': 100001001, 'debit': 0, 'tag': 'routed'},
        {'type': 'channel_mvt', 'credit': 0, 'debit': 50000000, 'tag': 'routed'},
        {'type': 'channel_mvt', 'credit': 100000000, 'debit': 0, 'tag': 'invoice'},
        {'type': 'channel_mvt', 'credit': 0, 'debit': 50000000, 'tag': 'invoice'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 100001000, 'tag': 'withdrawal'},
    ]
    if chainparams['elements']:
        l2_l3_mvts = [
            {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'channel_mvt', 'credit': 0, 'debit': 100000000, 'tag': 'routed'},
            {'type': 'channel_mvt', 'credit': 50000501, 'debit': 0, 'tag': 'routed'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 4477501, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 945523000, 'tag': 'withdrawal'},
        ]

        l2_wallet_mvts = [
            {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
            [
                {'type': 'chain_mvt', 'credit': 0, 'debit': 991908000, 'tag': 'withdrawal'},
                {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tag': 'withdrawal'},
            ],
            {'type': 'chain_mvt', 'credit': 0, 'debit': 8092000, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 991908000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 100001000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 945523000, 'debit': 0, 'tag': 'deposit'},
        ]
    elif EXPERIMENTAL_FEATURES:
        # option_anchor_outputs
        l2_l3_mvts = [
            {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'channel_mvt', 'credit': 0, 'debit': 100000000, 'tag': 'routed'},
            {'type': 'channel_mvt', 'credit': 50000501, 'debit': 0, 'tag': 'routed'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 4215501, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 945785000, 'tag': 'withdrawal'},
        ]

        l2_wallet_mvts = [
            {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
            # Could go in either order
            [
                {'type': 'chain_mvt', 'credit': 0, 'debit': 995433000, 'tag': 'withdrawal'},
                {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tag': 'withdrawal'},
            ],
            {'type': 'chain_mvt', 'credit': 0, 'debit': 4567000, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 995433000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 100001000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 945785000, 'debit': 0, 'tag': 'deposit'},
        ]
    else:
        l2_l3_mvts = [
            {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'channel_mvt', 'credit': 0, 'debit': 100000000, 'tag': 'routed'},
            {'type': 'channel_mvt', 'credit': 50000501, 'debit': 0, 'tag': 'routed'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 2715501, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 947285000, 'tag': 'withdrawal'},
        ]

        l2_wallet_mvts = [
            {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
            # Could go in either order
            [
                {'type': 'chain_mvt', 'credit': 0, 'debit': 995433000, 'tag': 'withdrawal'},
                {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tag': 'withdrawal'},
            ],
            {'type': 'chain_mvt', 'credit': 0, 'debit': 4567000, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 995433000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 100001000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 947285000, 'debit': 0, 'tag': 'deposit'},
        ]

    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {'may_reconnect': True},
        {'may_reconnect': True, 'plugin': os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')},
        {'may_reconnect': True},
    ], wait_for_announce=True)

    # Special case for dual-funded channel opens
    if l2.config('experimental-dual-fund'):
        l2_wallet_mvts = [
            {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 995410000, 'tag': 'withdrawal'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tag': 'withdrawal'},
            {'type': 'chain_mvt', 'credit': 0, 'debit': 4590000, 'tag': 'chain_fees'},
            {'type': 'chain_mvt', 'credit': 995410000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 100001000, 'debit': 0, 'tag': 'deposit'},
            {'type': 'chain_mvt', 'credit': 945785000, 'debit': 0, 'tag': 'deposit'},
        ]

    bitcoind.generate_block(5)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)
    amount = 10**8

    payment_hash13 = l3.rpc.invoice(amount, "first", "desc")['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    # status: offered -> settled
    l1.rpc.sendpay(route, payment_hash13)
    l1.rpc.waitsendpay(payment_hash13)

    # status: offered -> failed
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']
    payment_hash13 = "f" * 64
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash13)
        l1.rpc.waitsendpay(payment_hash13)

    # go the other direction
    payment_hash31 = l1.rpc.invoice(amount // 2, "first", "desc")['payment_hash']
    route = l3.rpc.getroute(l1.info['id'], amount // 2, 1)['route']
    l3.rpc.sendpay(route, payment_hash31)
    l3.rpc.waitsendpay(payment_hash31)

    # receive a payment (endpoint)
    payment_hash12 = l2.rpc.invoice(amount, "first", "desc")['payment_hash']
    route = l1.rpc.getroute(l2.info['id'], amount, 1)['route']
    l1.rpc.sendpay(route, payment_hash12)
    l1.rpc.waitsendpay(payment_hash12)

    # send a payment (originator)
    payment_hash21 = l1.rpc.invoice(amount // 2, "second", "desc")['payment_hash']
    route = l2.rpc.getroute(l1.info['id'], amount // 2, 1)['route']
    l2.rpc.sendpay(route, payment_hash21)
    l2.rpc.waitsendpay(payment_hash21)

    # restart to test index
    l2.restart()
    wait_for(lambda: all(p['channels'][0]['state'] == 'CHANNELD_NORMAL' for p in l2.rpc.listpeers()['peers']))

    # close the channels down
    chan1 = l2.get_channel_scid(l1)
    chan3 = l2.get_channel_scid(l3)
    chanid_1 = first_channel_id(l2, l1)
    chanid_3 = first_channel_id(l2, l3)

    l2.rpc.close(chan1)
    l2.daemon.wait_for_logs([
        ' to CLOSINGD_COMPLETE',
        'sendrawtx exit 0',
    ])
    assert account_balance(l2, chanid_1) == 100001001
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l2])
    l2.daemon.wait_for_log('{}.*FUNDING_TRANSACTION/FUNDING_OUTPUT->MUTUAL_CLOSE depth'.format(l1.info['id']))

    l2.rpc.close(chan3)
    l2.daemon.wait_for_logs([
        ' to CLOSINGD_COMPLETE',
        'sendrawtx exit 0',
    ])
    assert account_balance(l2, chanid_3) == 950000501
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l2])
    l2.daemon.wait_for_log('{}.*FUNDING_TRANSACTION/FUNDING_OUTPUT->MUTUAL_CLOSE depth'.format(l3.info['id']))

    # Ending channel balance should be zero
    assert account_balance(l2, chanid_1) == 0
    assert account_balance(l2, chanid_3) == 0

    # Verify we recorded all the movements we expect
    check_coin_moves(l2, chanid_1, l1_l2_mvts, chainparams)
    check_coin_moves(l2, chanid_3, l2_l3_mvts, chainparams)
    check_coin_moves(l2, 'wallet', l2_wallet_mvts, chainparams)
    check_coin_moves_idx(l2)


def test_3847_repro(node_factory, bitcoind):
    """Reproduces the issue in #3847: duplicate response from plugin

    l2 holds on to HTLCs until the deadline expires. Then we allow them
    through and either should terminate the payment attempt, and the second
    would return a redundant result.

    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {},
        {
            'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py'),
            'hold-time': 11,
            'hold-result': 'fail',
        },
    ], wait_for_announce=True)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)

    # Amount sufficient to trigger the presplit modifier
    amt = 20 * 1000 * 1000

    i1 = l3.rpc.invoice(
        msatoshi=amt, label="direct", description="desc"
    )['bolt11']
    with pytest.raises(RpcError):
        l1.rpc.pay(i1, retry_for=10)

    # We wait for at least two parts, and the bug would cause the `pay` plugin
    # to crash
    l1.daemon.wait_for_logs([r'Payment deadline expired, not retrying'] * 2)

    # This call to paystatus would fail if the pay plugin crashed (it's
    # provided by the plugin)
    l1.rpc.paystatus(i1)


def test_important_plugin(node_factory):
    # Cache it here.
    pluginsdir = os.path.join(os.path.dirname(__file__), "plugins")

    n = node_factory.get_node(options={"important-plugin": os.path.join(pluginsdir, "nonexistent")},
                              may_fail=True, expect_fail=True,
                              allow_broken_log=True, start=False)
    n.daemon.start(wait_for_initialized=False, stderr=subprocess.PIPE)
    wait_for(lambda: not n.daemon.running)

    assert n.daemon.is_in_stderr(r"error starting plugin '.*nonexistent'")

    # We use a log file, since our wait_for_log is unreliable when the
    # daemon actually dies.
    def get_logfile_match(logpath, regex):
        if not os.path.exists(logpath):
            return None
        with open(logpath, 'r') as f:
            for line in f.readlines():
                m = re.search(regex, line)
                if m is not None:
                    return m
        return None

    logpath = os.path.join(n.daemon.lightning_dir, TEST_NETWORK, 'logfile')
    n.daemon.opts['log-file'] = 'logfile'

    # Check we exit if the important plugin dies.
    n.daemon.opts['important-plugin'] = os.path.join(pluginsdir, "fail_by_itself.py")

    n.daemon.start(wait_for_initialized=False)
    wait_for(lambda: not n.daemon.running)

    assert get_logfile_match(logpath,
                             r'fail_by_itself.py: Plugin marked as important, shutting down lightningd')
    os.remove(logpath)

    # Check if the important plugin is disabled, we run as normal.
    n.daemon.opts['disable-plugin'] = "fail_by_itself.py"
    del n.daemon.opts['log-file']
    n.daemon.start()
    # Make sure we can call into a plugin RPC (this is from `bcli`) even
    # if fail_by_itself.py is disabled.
    n.rpc.call("estimatefees", {})
    # Make sure we are still running.
    assert n.daemon.running
    n.stop()

    # Check if an important plugin dies later, we fail.
    del n.daemon.opts['disable-plugin']
    n.daemon.opts['log-file'] = 'logfile'
    n.daemon.opts['important-plugin'] = os.path.join(pluginsdir, "suicidal_plugin.py")

    n.daemon.start(wait_for_initialized=False)
    wait_for(lambda: get_logfile_match(logpath, "Server started with public key"))

    with pytest.raises(RpcError):
        n.rpc.call("die", {})

    wait_for(lambda: not n.daemon.running)
    assert get_logfile_match(logpath, 'suicidal_plugin.py: Plugin marked as important, shutting down lightningd')
    os.remove(logpath)

    # Check that if a builtin plugin dies, we fail.
    n.daemon.start(wait_for_initialized=False)

    wait_for(lambda: get_logfile_match(logpath, r'.*started\(([0-9]*)\).*plugins/pay'))
    pidstr = get_logfile_match(logpath, r'.*started\(([0-9]*)\).*plugins/pay').group(1)

    # Kill pay.
    os.kill(int(pidstr), signal.SIGKILL)
    wait_for(lambda: not n.daemon.running)

    assert get_logfile_match(logpath, 'pay: Plugin marked as important, shutting down lightningd')


@unittest.skipIf(not DEVELOPER, "tests developer-only option.")
def test_dev_builtin_plugins_unimportant(node_factory):
    n = node_factory.get_node(options={"dev-builtin-plugins-unimportant": None})
    n.rpc.plugin_stop(plugin="pay")


def test_htlc_accepted_hook_crash(node_factory, executor):
    """Test that we do not hang incoming HTLCs if the hook plugin crashes.

    Reproduces #3748.
    """
    plugin = os.path.join(os.getcwd(), 'tests/plugins/htlc_accepted-crash.py')
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(
        options={'plugin': plugin},
        allow_broken_log=True
    )
    l1.connect(l2)
    l1.fundchannel(l2)

    i = l2.rpc.invoice(500, "crashpls", "crashpls")['bolt11']

    # This should still succeed

    f = executor.submit(l1.rpc.pay, i)

    l2.daemon.wait_for_log(r'Crashing on purpose...')
    l2.daemon.wait_for_log(
        r'Hook handler for htlc_accepted failed with an exception.'
    )

    with pytest.raises(RpcError, match=r'failed: WIRE_TEMPORARY_NODE_FAILURE'):
        f.result(10)


def test_notify(node_factory):
    """Test that notifications from plugins get ignored"""
    plugins = [os.path.join(os.getcwd(), 'tests/plugins/notify.py'),
               os.path.join(os.getcwd(), 'tests/plugins/notify2.py')]
    l1 = node_factory.get_node(options={'plugin': plugins})

    assert l1.rpc.call('make_notify') == 'This worked'
    assert l1.rpc.call('call_make_notify') == 'This worked'

    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'make_notify']).decode('utf-8').splitlines(keepends=True)
    assert out[0] == '# Beginning stage 1\n'
    assert out[1] == '\r'
    for i in range(100):
        assert out[2 + i].startswith("# Stage 1/2 {:>3}/100 |".format(1 + i))
        if i == 99:
            assert out[2 + i].endswith("|\n")
        else:
            assert out[2 + i].endswith("|\r")

    assert out[102] == '# Beginning stage 2\n'
    assert out[103] == '\r'

    for i in range(10):
        assert out[104 + i].startswith("# Stage 2/2 {:>2}/10 |".format(1 + i))
        if i == 9:
            assert out[104 + i].endswith("|\n")
        else:
            assert out[104 + i].endswith("|\r")
    assert out[114] == '"This worked"\n'
    assert len(out) == 115

    # At debug level, we get the second prompt.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-N', 'debug',
                                   'make_notify']).decode('utf-8').splitlines()
    assert out[0] == '# Beginning stage 1'
    assert out[1] == ''
    for i in range(100):
        assert out[2 + i].startswith("# Stage 1/2 {:>3}/100 |".format(1 + i))
        assert out[2 + i].endswith("|")
    assert out[102] == '# Beginning stage 2'
    assert out[103] == ''
    for i in range(10):
        assert out[104 + i].startswith("# Stage 2/2 {:>2}/10 |".format(1 + i))
        assert out[104 + i].endswith("|")
    assert out[114] == '"This worked"'
    assert len(out) == 115

    # none suppresses
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '--notifications=none',
                                   'make_notify']).decode('utf-8').splitlines()
    assert out == ['"This worked"']


def test_htlc_accepted_hook_failcodes(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/htlc_accepted-failcode.py')
    l1, l2 = node_factory.line_graph(2, opts=[{}, {'plugin': plugin}])

    # First let's test the newer failure_message, which should get passed
    # through without being mapped.
    tests = {
        '2002': 'WIRE_TEMPORARY_NODE_FAILURE',
        '400F' + 12 * '00': 'WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS',
        '4009': 'WIRE_REQUIRED_CHANNEL_FEATURE_MISSING',
        '4016' + 3 * '00': 'WIRE_INVALID_ONION_PAYLOAD',
    }

    for failmsg, expected in tests.items():
        l2.rpc.setfailcode(msg=failmsg)
        inv = l2.rpc.invoice(42, 'failmsg{}'.format(failmsg), '')['bolt11']
        with pytest.raises(RpcError, match=r'failcodename.: .{}.'.format(expected)):
            l1.rpc.pay(inv)

    # And now test the older failcode return value. This is deprecated and can
    # be removed once we have removed the failcode correction code in
    # peer_htlcs.c. The following ones get remapped
    tests.update({
        '400F': 'WIRE_TEMPORARY_NODE_FAILURE',
        '4009': 'WIRE_TEMPORARY_NODE_FAILURE',
        '4016': 'WIRE_TEMPORARY_NODE_FAILURE',
    })

    for failcode, expected in tests.items():
        # Do not attempt with full messages
        if len(failcode) > 4:
            continue

        l2.rpc.setfailcode(code=failcode)
        inv = l2.rpc.invoice(42, 'failcode{}'.format(failcode), '')['bolt11']
        with pytest.raises(RpcError, match=r'failcodename.: .{}.'.format(expected)):
            l1.rpc.pay(inv)


def test_hook_dep(node_factory):
    dep_a = os.path.join(os.path.dirname(__file__), 'plugins/dep_a.py')
    dep_b = os.path.join(os.path.dirname(__file__), 'plugins/dep_b.py')
    dep_c = os.path.join(os.path.dirname(__file__), 'plugins/dep_c.py')
    l1, l2, l3 = node_factory.line_graph(3, opts=[{},
                                                  {'plugin': dep_b},
                                                  {'plugin': [dep_a, dep_b]}])

    # l2 complains about the two unknown plugins, only.
    # (Could be already past)
    l2.daemon.logsearch_start = 0
    l2.daemon.wait_for_logs(["unknown plugin dep_a.py",
                             "unknown plugin dep_c.py"])
    assert not l2.daemon.is_in_log("unknown plugin (?!dep_a.py|dep_c.py)")
    logstart = l2.daemon.logsearch_start

    # l3 complains about the dep_c, only.
    assert l3.daemon.is_in_log("unknown plugin dep_c.py")
    assert not l3.daemon.is_in_log("unknown plugin (?!dep_c.py)")

    # A says it has to be before B.
    l2.rpc.plugin_start(plugin=dep_a)
    l2.daemon.wait_for_log(r"started.*dep_a.py")
    # Still doesn't know about c.
    assert l2.daemon.is_in_log("unknown plugin dep_c.py", logstart)

    l1.pay(l2, 100000)
    # They must be called in this order!
    l2.daemon.wait_for_log(r"dep_a.py: htlc_accepted called")
    l2.daemon.wait_for_log(r"dep_b.py: htlc_accepted called")

    # But depc will not load, due to cyclical dep
    with pytest.raises(RpcError, match=r'Cannot meet required hook dependencies'):
        l2.rpc.plugin_start(plugin=dep_c)

    l1.rpc.plugin_start(plugin=dep_c)
    l1.daemon.wait_for_log(r"started.*dep_c.py")

    # Complaints about unknown plugin a, but nothing else
    assert l1.daemon.is_in_log("unknown plugin dep_a.py")
    assert not l1.daemon.is_in_log("unknown plugin (?!dep_a.py)")


def test_hook_dep_stable(node_factory):
    # Load in order A, D, E, B.
    # A says it has to be before B, D says it has to be before E.
    # It should load in the order specified.

    dep_a = os.path.join(os.path.dirname(__file__), 'plugins/dep_a.py')
    dep_b = os.path.join(os.path.dirname(__file__), 'plugins/dep_b.py')
    dep_d = os.path.join(os.path.dirname(__file__), 'plugins/dep_d.py')
    dep_e = os.path.join(os.path.dirname(__file__), 'plugins/dep_e.py')
    l1, l2 = node_factory.line_graph(2, opts=[{},
                                              {'plugin': [dep_a, dep_d, dep_e, dep_b]}])

    # dep_a mentions deb_c, but nothing else should be unknown.
    # (Could be already past)
    l2.daemon.logsearch_start = 0
    l2.daemon.wait_for_log("unknown plugin dep_c.py")
    assert not l2.daemon.is_in_log("unknown plugin (?!|dep_c.py)")

    l1.pay(l2, 100000)
    # They must be called in this order!
    l2.daemon.wait_for_log(r"dep_a.py: htlc_accepted called")
    l2.daemon.wait_for_log(r"dep_d.py: htlc_accepted called")
    l2.daemon.wait_for_log(r"dep_e.py: htlc_accepted called")
    l2.daemon.wait_for_log(r"dep_b.py: htlc_accepted called")


def test_htlc_accepted_hook_failonion(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/htlc_accepted-failonion.py')
    l1, l2 = node_factory.line_graph(2, opts=[{}, {'plugin': plugin}])

    # an invalid onion
    l2.rpc.setfailonion('0' * (292 * 2))
    inv = l2.rpc.invoice(42, 'failonion000', '')['bolt11']
    with pytest.raises(RpcError):
        l1.rpc.pay(inv)


def test_dynamic_args(node_factory):
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')

    l1 = node_factory.get_node()
    l1.rpc.plugin_start(plugin_path, greeting='Test arg parsing')

    assert l1.rpc.call("hello") == "Test arg parsing world"
    plugin = only_one([p for p in l1.rpc.listconfigs()['plugins'] if p['path'] == plugin_path])
    assert plugin['options']['greeting'] == 'Test arg parsing'

    l1.rpc.plugin_stop(plugin_path)

    assert [p for p in l1.rpc.listconfigs()['plugins'] if p['path'] == plugin_path] == []


def test_pyln_request_notify(node_factory):
    """Test that pyln-client plugins can send notifications.
    """
    plugin_path = os.path.join(
        os.path.dirname(__file__), 'plugins/countdown.py'
    )
    l1 = node_factory.get_node(options={'plugin': plugin_path})
    notifications = []

    def n(*args, message, **kwargs):
        print("Got a notification:", message)
        notifications.append(message)

    with l1.rpc.notify(n):
        l1.rpc.countdown(10)

    expected = ['{}/10'.format(i) for i in range(10)]
    assert expected == notifications

    # Calling without the context manager we should not get any notifications
    notifications = []
    l1.rpc.countdown(10)
    assert notifications == []


def test_self_disable(node_factory):
    """Test that plugin can disable itself without penalty.
    """
    # This disables in response to getmanifest.
    p1 = os.path.join(
        os.path.dirname(__file__), 'plugins/test_selfdisable_after_getmanifest'
    )
    # This disables in response to init.
    p2 = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = node_factory.get_node(options={'important-plugin': [p1, p2], 'selfdisable': None})

    # Could happen before it gets set up.
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs(['test_selfdisable_after_getmanifest: .* disabled itself: Self-disable test after getmanifest',
                             'test_libplugin: .* disabled itself at init: Disabled via selfdisable option'])

    assert p1 not in [p['name'] for p in l1.rpc.plugin_list()['plugins']]
    assert p2 not in [p['name'] for p in l1.rpc.plugin_list()['plugins']]

    # Also works with dynamic load attempts
    with pytest.raises(RpcError, match="Self-disable test after getmanifest"):
        l1.rpc.plugin_start(p1)

    # Also works with dynamic load attempts
    with pytest.raises(RpcError, match="Disabled via selfdisable option"):
        l1.rpc.plugin_start(p2, selfdisable=True)
