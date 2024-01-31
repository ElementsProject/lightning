from collections import OrderedDict
from datetime import datetime
from fixtures import *  # noqa: F401,F403
from hashlib import sha256
from pyln.client import RpcError, Millisatoshi
from pyln.proto import Invoice
from pyln.testing.utils import FUNDAMOUNT
from utils import (
    only_one, sync_blockheight, TIMEOUT, wait_for, TEST_NETWORK,
    expected_peer_features, expected_node_features,
    expected_channel_features, account_balance,
    check_coin_moves, first_channel_id, EXPERIMENTAL_DUAL_FUND,
    mine_funding_to_announce, VALGRIND
)

import ast
import base64
import json
import os
import pytest
import random
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import unittest


def test_option_passthrough(node_factory, directory):
    """ Ensure that registering options works.

    First attempts without the plugin and then with the plugin.
    Then a plugin tries to register the same option "name" again, fails startup.
    """
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')
    plugin_path2 = os.path.join(os.getcwd(), 'tests/plugins/options.py')

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

    with pytest.raises(subprocess.CalledProcessError):
        err_out = subprocess.run([
            'lightningd/lightningd',
            '--lightning-dir={}'.format(directory),
            '--plugin={}'.format(plugin_path),
            '--plugin={}'.format(plugin_path2),
            '--help'
        ], capture_output=True, check=True).stderr.decode('utf-8')

        # first come first serve
        assert("error starting plugin '{}': option name 'greeting' is already taken".format(plugin_path2) in err_out)


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
    }, may_fail=True, start=False)

    # the node should fail after start, and we get a stderr msg
    n.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert n.daemon.wait() == 1
    wait_for(lambda: n.daemon.is_in_stderr("--bool_opt=!: Invalid argument '!'"))

    # What happens if we give it a bad int-option?
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 'notok',
        'bool_opt': True,
    }, may_fail=True, start=False)

    # the node should fail after start, and we get a stderr msg
    n.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert n.daemon.wait() == 1
    assert n.daemon.is_in_stderr("--int_opt=notok: 'notok' is not a number")

    # We no longer allow '1' or '0' as boolean options
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'bool_opt': '1',
    }, may_fail=True, start=False)

    # the node should fail after start, and we get a stderr msg
    n.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert n.daemon.wait() == 1
    assert n.daemon.is_in_stderr("--bool_opt=1: boolean plugin arguments must be true or false")

    # Flag opts shouldn't allow any input
    n = node_factory.get_node(options={
        'plugin': plugin_path,
        'str_opt': 'ok',
        'int_opt': 11,
        'bool_opt': True,
        'flag_opt': True,
    }, may_fail=True, start=False)

    # the node should fail after start, and we get a stderr msg
    n.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert n.daemon.wait() == 1
    assert n.daemon.is_in_stderr("--flag_opt=True: doesn't allow an argument")

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

    # By keyword (plugin literally returns Millisatoshi, which becomes a string)
    ret = n.rpc.call('echo', {'msat': Millisatoshi(17), 'not_an_msat': '22msat'})['echo_msat']
    assert Millisatoshi(ret) == Millisatoshi(17)

    # By position
    ret = n.rpc.call('echo', [Millisatoshi(18), '22msat'])['echo_msat']
    assert Millisatoshi(ret) == Millisatoshi(18)


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
    n.stop()

    # Also works by basename.
    n = node_factory.get_node(options=OrderedDict([('plugin-dir', plugin_dir),
                                                   ('disable-plugin',
                                                    'helloworld.py')]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')
    n.stop()

    # Other order also works!
    n = node_factory.get_node(options=OrderedDict([('disable-plugin',
                                                    'helloworld.py'),
                                                   ('plugin-dir', plugin_dir)]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')
    n.stop()

    # Both orders of explicit specification work.
    n = node_factory.get_node(options=OrderedDict([('disable-plugin',
                                                    'helloworld.py'),
                                                   ('plugin',
                                                    '{}/helloworld.py'
                                                    .format(plugin_dir))]))
    with pytest.raises(RpcError):
        n.rpc.hello(name='Sun')
    assert n.daemon.is_in_log('helloworld.py: disabled via disable-plugin')
    n.stop()

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
    n.stop()

    # Check that list works
    n = node_factory.get_node(options={'disable-plugin':
                                       ['something-else.py', 'helloworld.py']})

    assert n.rpc.listconfigs()['configs']['disable-plugin'] == {'values_str': ['something-else.py', 'helloworld.py'], 'sources': ['cmdline', 'cmdline']}


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
    msg = 'pay bolt11 [amount_msat] [label] [riskfactor] [maxfeepercent] '\
          '[retry_for] [maxdelay] [exemptfee] [localinvreqid] [exclude] '\
          '[maxfee] [description]'
    # We run with --developer:
    msg += ' [dev_use_shadow]'
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

    # If reject happens fast enough, connect fails with "disconnected
    # during connection"
    try:
        l3.connect(l1)
    except RpcError as err:
        assert "disconnected during connection" in err.error['message']

    l1.daemon.wait_for_logs([
        f"peer_connected_logger_a {l3id}",
        f"{l3id} is in reject list"
    ])

    # FIXME: this error occurs *after* connection, so we connect then drop.
    l3.daemon.wait_for_log(r"-connectd: peer_in WIRE_WARNING")
    l3.daemon.wait_for_log(r"You are in reject list")

    def check_disconnect():
        peers = l1.rpc.listpeers(l3id)['peers']
        return peers == [] or not peers[0]['connected']

    wait_for(check_disconnect)
    assert not l1.daemon.is_in_log(f"peer_connected_logger_b {l3id}")


def test_peer_connected_remote_addr(node_factory):
    """This tests the optional tlv `remote_addr` being passed to a plugin.

    The optional tlv `remote_addr` should only be visible to the initiator l1.
    """
    pluginpath = os.path.join(os.getcwd(), 'tests/plugins/peer_connected_logger_a.py')
    l1, l2 = node_factory.get_nodes(2, opts={
        'plugin': pluginpath,
        'dev-allow-localhost': None})
    l1id = l1.info['id']
    l2id = l2.info['id']

    l1.connect(l2)
    l1log = l1.daemon.wait_for_log(f"peer_connected_logger_a {l2id}")
    l2log = l2.daemon.wait_for_log(f"peer_connected_logger_a {l1id}")

    # the log entries are followed by the peer_connected payload as dict {} like:
    # {'id': '022d223...', 'direction': 'out', 'addr': '127.0.0.1:35289',
    #  'remote_addr': '127.0.0.1:59582', 'features': '8808226aa2'}
    l1payload = eval(l1log[l1log.find('{'):])
    l2payload = eval(l2log[l2log.find('{'):])

    # check that l1 sees its remote_addr as l2 sees l1
    assert(l1payload['remote_addr'] == l2payload['addr'])
    assert(not l2payload.get('remote_addr'))  # l2 can't see a remote_addr


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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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
        'dust_limit_msat': 546000,
        'htlc_minimum_msat': 0,
        'id': l1.info['id'],
        'max_accepted_htlcs': '483',
        'max_htlc_value_in_flight_msat': 18446744073709551615,
        'to_self_delay': '5',
    }

    if l2.config('experimental-dual-fund'):
        # openchannel2 var checks
        expected.update({
            'channel_id': '.*',
            'channel_max_msat': 2100000000000000000,
            'commitment_feerate_per_kw': '7500',
            'funding_feerate_per_kw': '7500',
            'feerate_our_max': '150000',
            'feerate_our_min': '1875',
            'locktime': '.*',
            'require_confirmed_inputs': False,
            'their_funding_msat': 100000000,
        })
    else:
        expected.update({
            'channel_reserve_msat': 1000000,
            'feerate_per_kw': '7500',
            'funding_msat': 100000000,
            'push_msat': 0,
        })

    l2.daemon.wait_for_log('reject_odd_funding_amounts.py: {} VARS'.format(len(expected)))
    for k, v in expected.items():
        assert l2.daemon.is_in_log('reject_odd_funding_amounts.py: {}={}'.format(k, v))

    # Close it.
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(1, txid)
    wait_for(lambda: [c['state'] for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']] == ['ONCHAIN'])

    # Odd amount: fails
    l1.connect(l2)
    with pytest.raises(RpcError, match=r"I don't like odd amounts"):
        l1.rpc.fundchannel(l2.info['id'], 100001)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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
    with pytest.raises(RpcError, match=r'reject for a reason'):
        l1.rpc.fundchannel(l2.info['id'], 100005)

    assert l2.daemon.wait_for_log(hook_msg + "reject for a reason")
    # first plugin in the chain was called
    assert l2.daemon.is_in_log("accept on principle")
    # the third plugin must now not be called anymore
    assert not l2.daemon.is_in_log("reject on principle")

    assert only_one(l1.rpc.listpeers()['peers'])['connected']
    # 100000sat is good for hook_accepter, so it should fail 'on principle'
    # at third hook openchannel_reject.py
    with pytest.raises(RpcError, match=r'reject on principle'):
        l1.rpc.fundchannel(l2.info['id'], 100000)
    assert l2.daemon.wait_for_log(hook_msg + "reject on principle")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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
    assert(l1.rpc.listpeerchannels()['channels'][0]['opener'] == 'local')
    assert(l2.rpc.listpeerchannels()['channels'][0]['opener'] == 'remote')
    # the 'closer' should be missing initially
    assert 'closer' not in l1.rpc.listpeerchannels()['channels'][0]
    assert 'closer' not in l2.rpc.listpeerchannels()['channels'][0]

    if l1.config('experimental-dual-fund'):
        # Dual funded channels go through three state transitions.
        event1a, event1b, event1c = wait_for_event(l1), wait_for_event(l1), wait_for_event(l1)
        event2a, event2b, event2c = wait_for_event(l2), wait_for_event(l2), wait_for_event(l2)

        for ev in [event1a, event1b]:
            assert(ev['peer_id'] == l2_id)  # we only test these IDs the first time
            assert(ev['channel_id'] == cid)
            assert(ev['short_channel_id'] is None)  # None until locked in
            assert(ev['cause'] == "remote")

        for ev in [event2a, event2b]:
            assert(ev['peer_id'] == l1_id)  # we only test these IDs the first time
            assert(ev['channel_id'] == cid)
            assert(ev['short_channel_id'] is None)  # None until locked in
            assert(ev['cause'] == "remote")

        for ev in [event1a, event2a]:
            assert(ev['old_state'] == "DUALOPEND_OPEN_INIT")
            assert(ev['new_state'] == "DUALOPEND_OPEN_COMMIT_READY")
            assert(ev['message'] == "Ready to send our commitment sigs")

        for ev in [event1b, event2b]:
            assert(ev['old_state'] == "DUALOPEND_OPEN_COMMIT_READY")
            assert(ev['new_state'] == "DUALOPEND_OPEN_COMMITTED")
            assert(ev['message'] == "Commitment transaction committed")

        for ev in [event1c, event2c]:
            assert(ev['old_state'] == "DUALOPEND_OPEN_COMMITTED")
            assert(ev['new_state'] == "DUALOPEND_AWAITING_LOCKIN")
            assert(ev['message'] == "Sigs exchanged, waiting for lock-in")
    else:
        event1 = wait_for_event(l1)
        event2 = wait_for_event(l2)
        assert(event1['peer_id'] == l2_id)  # we only test these IDs the first time
        assert(event1['channel_id'] == cid)
        assert(event1['short_channel_id'] is None)  # None until locked in
        assert(event1['cause'] == "user")

        assert(event2['peer_id'] == l1_id)  # we only test these IDs the first time
        assert(event2['channel_id'] == cid)
        assert(event2['short_channel_id'] is None)  # None until locked in
        assert(event2['cause'] == "remote")

        for ev in [event1, event2]:
            assert(ev['old_state'] == "unknown")
            assert(ev['new_state'] == "CHANNELD_AWAITING_LOCKIN")
            assert(ev['message'] == "new channel opened")

    event1 = wait_for_event(l1)
    event2 = wait_for_event(l2)
    assert(event1['short_channel_id'] == scid)
    if l1.config('experimental-dual-fund'):
        assert(event1['old_state'] == "DUALOPEND_AWAITING_LOCKIN")
    else:
        assert(event1['old_state'] == "CHANNELD_AWAITING_LOCKIN")
    assert(event1['new_state'] == "CHANNELD_NORMAL")
    assert(event1['cause'] == "user")
    assert(event1['message'] == "Lockin complete")

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
    assert(l1.rpc.listpeerchannels()['channels'][0]['closer'] == 'local')
    assert(l2.rpc.listpeerchannels()['channels'][0]['closer'] == 'remote')

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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_channel_state_changed_unilateral(node_factory, bitcoind):
    """ We open, disconnect, force-close a channel and check for notifications.

    The misc_notifications.py plugin logs `channel_state_changed` events.
    """
    opts = {"plugin": os.path.join(os.getcwd(), "tests/plugins/misc_notifications.py"),
            "allow_warning": True,
            'may_reconnect': True}

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
    assert(event2['peer_id'] == l1_id)
    assert(event2['channel_id'] == cid)
    assert(event2['short_channel_id'] is None)
    assert(event2['cause'] == "remote")

    if l2.config('experimental-dual-fund'):
        assert(event2['old_state'] == "DUALOPEND_OPEN_INIT")
        assert(event2['new_state'] == "DUALOPEND_OPEN_COMMIT_READY")
        assert(event2['message'] == "Ready to send our commitment sigs")

        event2 = wait_for_event(l2)
        assert event2['old_state'] == "DUALOPEND_OPEN_COMMIT_READY"
        assert event2['new_state'] == "DUALOPEND_OPEN_COMMITTED"
        assert event2['message'] == "Commitment transaction committed"

        event2 = wait_for_event(l2)
        assert event2['old_state'] == "DUALOPEND_OPEN_COMMITTED"
        assert event2['new_state'] == "DUALOPEND_AWAITING_LOCKIN"
        assert event2['message'] == "Sigs exchanged, waiting for lock-in"
    else:
        assert(event2['old_state'] == "unknown")
        assert(event2['new_state'] == "CHANNELD_AWAITING_LOCKIN")
        assert(event2['message'] == "new channel opened")

    event2 = wait_for_event(l2)
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

    # restart l1 now, it will reconnect and l2 will send it an error.
    l1.restart()
    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 1)
    # check 'closer' on l2 while the peer is not yet forgotten
    assert(l2.rpc.listpeerchannels()['channels'][0]['closer'] == 'local')
    if EXPERIMENTAL_DUAL_FUND:
        l1.daemon.wait_for_log(r'Peer has reconnected, state')
        l2.daemon.wait_for_log(r'Telling connectd to send error')

    # l1 will receive error, and go into AWAITING_UNILATERAL
    # FIXME: l2 should re-xmit shutdown, but it doesn't until it's mined :(
    event1 = wait_for_event(l1)
    # Doesn't have closer, since it blames the "protocol"?
    assert 'closer' not in l1.rpc.listpeerchannels()['channels'][0]
    assert(event1['old_state'] == "CHANNELD_NORMAL")
    assert(event1['new_state'] == "AWAITING_UNILATERAL")
    assert(event1['cause'] == "protocol")
    assert(event1['message'] == "channeld: received ERROR channel {}: Forcibly closed by `close` command timeout".format(cid))

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
    assert(l1.rpc.listpeerchannels()['channels'][0]['closer'] == 'remote')

    assert(event1['old_state'] == "AWAITING_UNILATERAL")
    assert(event1['new_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['cause'] == "onchain")
    assert(event1['message'] == "Onchain funding spend")

    event1 = wait_for_event(l1)
    assert(event1['old_state'] == "FUNDING_SPEND_SEEN")
    assert(event1['new_state'] == "ONCHAIN")
    assert(event1['cause'] == "onchain")
    assert(event1['message'] == "Onchain init reply")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_channel_state_change_history(node_factory, bitcoind):
    """ We open and close a channel and check for state_canges entries.

    """
    l1, l2 = node_factory.line_graph(2)
    scid = l1.get_channel_scid(l2)
    l1.rpc.close(scid)

    history = l1.rpc.listpeerchannels()['channels'][0]['state_changes']
    if l1.config('experimental-dual-fund'):
        assert(history[0]['cause'] == "user")
        assert(history[0]['old_state'] == "DUALOPEND_OPEN_COMMITTED")
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


def test_htlc_accepted_hook_fail(node_factory):
    """Send payments from l1 to l2, but l2 just declines everything.

    l2 is configured with a plugin that'll hook into htlc_accepted and
    always return failures. The same should also work for forwarded
    htlcs in the second half.

    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {'dev-onion-reply-length': 1111,
         'plugin': os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')},
        {}
    ], wait_for_announce=True)

    # This must fail
    inv = l2.rpc.invoice(1000, "lbl", "desc")
    phash = inv['payment_hash']
    route = l1.rpc.getroute(l2.info['id'], 1000, 1)['route']

    # Here shouldn't use `pay` command because l2 rejects with WIRE_TEMPORARY_NODE_FAILURE,
    # then it will be excluded when l1 try another pay attempt.
    # Note if the destination is excluded, the route result is undefined.
    l1.rpc.sendpay(route, phash, payment_secret=inv['payment_secret'])
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


def test_htlc_accepted_hook_resolve(node_factory):
    """l3 creates an invoice, l2 knows the preimage and will shortcircuit.
    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {},
        {'plugin': os.path.join(os.getcwd(), 'tests/plugins/shortcircuit.py')},
        {}
    ], wait_for_announce=True)

    inv = l3.rpc.invoice(amount_msat=1000, label="lbl", description="desc", preimage="00" * 32)['bolt11']
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

    i1 = l2.rpc.invoice(amount_msat=1000, label="direct", description="desc")['bolt11']
    f1 = executor.submit(l1.rpc.pay, i1)

    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')

    # Check that the status mentions the HTLC being held
    l2.rpc.listpeers()
    channel = only_one(l2.rpc.listpeerchannels()['channels'])
    htlc_status = channel['htlcs'][0].get('status', None)
    assert htlc_status == "Waiting for the htlc_accepted hook of plugin hold_htlcs.py"

    needle = l2.daemon.logsearch_start
    l2.restart()

    # Now it should try again, *after* initializing.
    # This may be before "Server started with public key" swallowed by restart()
    l2.daemon.logsearch_start = needle + 1
    l2.daemon.wait_for_log(r'hold_htlcs.py initializing')
    l2.daemon.wait_for_log(r'Holding onto an incoming htlc for 10 seconds')
    f1.result()


def test_htlc_accepted_hook_forward_restart(node_factory, executor):
    """l2 restarts while it is pondering what to do with an HTLC.
    """
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {'may_reconnect': True},
        {'may_reconnect': True,
         'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py')},
        {'may_reconnect': True},
    ], wait_for_announce=True)

    i1 = l3.rpc.invoice(amount_msat=1000, label="direct", description="desc")['bolt11']
    f1 = executor.submit(l1.dev_pay, i1, dev_use_shadow=False)

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
    assert onion['forward_msat'] == Millisatoshi(1000)
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
    l1.dev_pay(inv1['bolt11'], dev_use_shadow=False)

    l2.daemon.wait_for_log(r"Received invoice_payment event for label {},"
                           " preimage {}, and amount of {}"
                           .format(label, preimage, msats))


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
                           " preimage {}, and amount of {}"
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

    inv = l3.rpc.invoice(amount, "first", "desc")
    payment_hash13 = inv['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    # status: offered -> settled
    l1.rpc.sendpay(route, payment_hash13, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(payment_hash13)

    # status: offered -> failed
    route = l1.rpc.getroute(l4.info['id'], amount, 1)['route']
    payment_hash14 = "f" * 64
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash14, payment_secret="f" * 64)
        l1.rpc.waitsendpay(payment_hash14)

    # status: offered -> local_failed
    inv = l5.rpc.invoice(amount, 'onchain_timeout', 'desc')
    payment_hash15 = inv['payment_hash']
    fee = amount * 10 // 1000000 + 1
    c12 = l1.get_channel_scid(l2)
    c25 = l2.get_channel_scid(l5)
    route = [{'amount_msat': amount + fee - 1,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'amount_msat': amount - 1,
              'id': l5.info['id'],
              'delay': 5,
              'channel': c25}]

    executor.submit(l1.rpc.sendpay, route, payment_hash15, payment_secret=inv['payment_secret'])

    l5.daemon.wait_for_log('permfail')
    l5.wait_for_channel_onchain(l2.info['id'])
    l2.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l5.daemon.wait_for_log(' to ONCHAIN')

    _, txid, blocks = l2.wait_for_onchaind_tx('OUR_HTLC_TIMEOUT_TO_US',
                                              'THEIR_UNILATERAL/OUR_HTLC')
    assert blocks == 5
    bitcoind.generate_block(5)

    # Could be RBF!
    l2.mine_txid_or_rbf(txid)
    l2.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
    l5.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l2])

    stats = l2.rpc.listforwards()['forwards']
    assert len(stats) == 3
    plugin_stats = l2.rpc.call('listforwards_plugin')['forwards']
    assert len(plugin_stats) == 6

    # We don't have payment_hash in listforwards any more.
    for p in plugin_stats:
        del p['payment_hash']

    # use stats to build what we expect went to plugin.
    expect = stats[0].copy()
    # First event won't have conclusion.
    del expect['resolved_time']
    del expect['out_htlc_id']
    del expect['updated_index']
    expect['status'] = 'offered'
    assert plugin_stats[0] == expect
    expect = stats[0].copy()
    del expect['out_htlc_id']
    # We don't bother populating created_index for updates.
    del expect['created_index']
    assert plugin_stats[1] == expect

    expect = stats[1].copy()
    del expect['resolved_time']
    del expect['out_htlc_id']
    del expect['updated_index']
    expect['status'] = 'offered'
    assert plugin_stats[2] == expect
    expect = stats[1].copy()
    del expect['out_htlc_id']
    # We don't bother populating created_index for updates.
    del expect['created_index']
    assert plugin_stats[3] == expect

    expect = stats[2].copy()
    del expect['failcode']
    del expect['failreason']
    del expect['out_htlc_id']
    del expect['updated_index']
    expect['status'] = 'offered'
    assert plugin_stats[4] == expect
    expect = stats[2].copy()
    del expect['out_htlc_id']
    # We don't bother populating created_index for updates.
    del expect['created_index']
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

    inv1 = l3.rpc.invoice(amount, "first", "desc")
    payment_hash1 = inv1['payment_hash']
    inv2 = l3.rpc.invoice(amount, "second", "desc")
    payment_hash2 = inv2['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l1.rpc.sendpay(route, payment_hash1, payment_secret=inv1['payment_secret'])
    response1 = l1.rpc.waitsendpay(payment_hash1)

    l2.rpc.close(chanid23, 1)

    l1.rpc.sendpay(route, payment_hash2, payment_secret=inv2['payment_secret'])
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

    inv1 = l3.rpc.invoice(amount, "first", "desc")
    payment_hash1 = inv1['payment_hash']
    inv2 = l3.rpc.invoice(amount, "second", "desc")
    payment_hash2 = inv2['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l1.rpc.sendpay(route, payment_hash1, payment_secret=inv1['payment_secret'])
    l1.daemon.wait_for_log(r'Received a sendpay_success')

    l2.rpc.close(chanid23, 1)

    l1.rpc.sendpay(route, payment_hash2, payment_secret=inv2['payment_secret'])
    l1.daemon.wait_for_log(r'Received a sendpay_failure')

    results = l1.rpc.call('listsendpays_plugin')
    assert len(results['sendpay_success']) == 1
    assert len(results['sendpay_failure']) == 1


def test_rpc_command_hook(node_factory):
    """Test the `rpc_command` hook chain"""
    plugin = [
        os.path.join(os.getcwd(), "tests/plugins/rpc_command_1.py"),
        os.path.join(os.getcwd(), "tests/plugins/rpc_command_2.py")
    ]
    l1 = node_factory.get_node(options={"plugin": plugin})

    # rpc_command_2 plugin restricts using "sendpay"
    with pytest.raises(RpcError, match=r"rpc_command_2 cannot do this"):
        l1.rpc.call("sendpay")

    # Both plugins will replace calls made for the "invoice" command
    # The first will win, for the second a warning should be logged
    invoice = l1.rpc.invoice(10**6, "test_side", "test_input")
    decoded = l1.rpc.decodepay(invoice["bolt11"])
    assert decoded["description"] == "rpc_command_1 modified this description"
    l1.daemon.wait_for_log("rpc_command hook 'invoice' already modified, ignoring.")

    # Disable schema checking here!
    schemas = l1.rpc.jsonschemas
    l1.rpc.jsonschemas = {}
    # rpc_command_1 plugin sends a custom response to "listfunds"
    funds = l1.rpc.listfunds()
    assert funds[0] == "Custom rpc_command_1 result"

    # Test command redirection to a plugin
    l1.rpc.call('help', ['developer'])

    # Check the 'already modified' warning is not logged on just 'continue'
    assert not l1.daemon.is_in_log("rpc_command hook 'listfunds' already modified, ignoring.")

    # Tests removing a chained hook in random order.
    # Note: This will get flaky by design if theres a problem.
    if bool(random.getrandbits(1)):
        l1.rpc.plugin_stop('rpc_command_2.py')
        l1.rpc.plugin_stop('rpc_command_1.py')
    else:
        l1.rpc.plugin_stop('rpc_command_1.py')
        l1.rpc.plugin_stop('rpc_command_2.py')

    l1.rpc.jsonschemas = schemas


def test_libplugin(node_factory):
    """Sanity checks for plugins made with libplugin"""
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = node_factory.get_node(options={"plugin": plugin,
                                        'allow-deprecated-apis': False,
                                        'log-level': 'io'},
                               allow_broken_log=True)

    # Test startup
    assert l1.daemon.is_in_log("test_libplugin initialised!")
    assert l1.daemon.is_in_log("String name from datastore:.*token has no index 0")
    assert l1.daemon.is_in_log("Hex name from datastore:.*token has no index 0")

    # This will look on datastore for default, won't find it.
    assert l1.rpc.call("helloworld") == {"hello": "NOT FOUND"}
    l1.daemon.wait_for_log("get_ds_bin_done: NOT FOUND")

    # Test dynamic startup
    l1.rpc.plugin_stop(plugin)
    # Non-string datastore value:
    l1.rpc.datastore(["test_libplugin", "name"], hex="00010203")
    l1.rpc.plugin_start(plugin)
    l1.rpc.check("helloworld")

    myname = os.path.splitext(os.path.basename(sys.argv[0]))[0]

    # Note: getmanifest always uses numeric ids, since it doesn't know
    # yet whether strings are allowed:
    l1.daemon.wait_for_log(r"test_libplugin: [0-9]*\[OUT\]")

    l1.daemon.wait_for_log("String name from datastore:.*object does not have member string")
    l1.daemon.wait_for_log("Hex name from datastore: 00010203")

    # Test commands
    assert l1.rpc.call("helloworld") == {"hello": "NOT FOUND"}
    l1.daemon.wait_for_log("get_ds_bin_done: 00010203")
    l1.daemon.wait_for_log("BROKEN.* Datastore gave nonstring result.*00010203")
    assert l1.rpc.call("helloworld", {"name": "test"}) == {"hello": "test"}
    l1.stop()
    l1.daemon.opts["plugin"] = plugin
    l1.daemon.opts["somearg"] = "test_opt"
    l1.start()
    assert l1.daemon.is_in_log("somearg = test_opt")
    l1.rpc.datastore(["test_libplugin", "name"], "foobar", mode="must-replace")

    assert l1.rpc.call("helloworld") == {"hello": "foobar"}
    l1.daemon.wait_for_log("get_ds_bin_done: 666f6f626172")

    # But param takes over!
    assert l1.rpc.call("helloworld", {"name": "test"}) == {"hello": "test"}

    # Test hooks and notifications (add plugin, so we can test hook id)
    l2 = node_factory.get_node(options={"plugin": plugin, 'log-level': 'io'})
    l2.connect(l1)
    l2.daemon.wait_for_log(r': "{}:connect#[0-9]*/cln:peer_connected#[0-9]*"\[OUT\]'.format(myname))

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

    assert 'somearg-deprecated' not in str(l1.rpc.listconfigs()['configs'])

    l1.stop()
    l1.daemon.opts["somearg-deprecated"] = "test_opt"

    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr(r"somearg-deprecated=test_opt: deprecated option")

    del l1.daemon.opts["somearg-deprecated"]
    l1.start()


def test_libplugin_deprecated(node_factory):
    """Sanity checks for plugins made with libplugin using deprecated args"""
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = node_factory.get_node(options={"plugin": plugin,
                                        'somearg-deprecated': 'test_opt depr',
                                        'allow-deprecated-apis': True},
                               # testrpc-deprecated causes a complaint!
                               allow_broken_log=True)

    assert l1.daemon.is_in_log("somearg = test_opt depr")
    l1.rpc.help('testrpc-deprecated')
    assert l1.rpc.call("testrpc-deprecated") == l1.rpc.getinfo()


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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

    # Check the featurebits we've set in the `init` message from
    # feature-test.py.
    assert l1.daemon.is_in_log(r'\[OUT\] 001000021100....{}'
                               .format(expected_peer_features(extra=[201])))

    # Check the invoice featurebit we set in feature-test.py
    inv = l1.rpc.invoice(123, 'lbl', 'desc')['bolt11']
    details = Invoice.decode(inv)
    assert(details.featurebits.int & (1 << 205) != 0)

    # Check the featurebit set in the `node_announcement`
    node = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['features'] == expected_node_features(extra=[203])


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
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_log("Missing a Bitcoin plugin command")
    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr(r"Could not access the plugin for sendrawtransaction")
    # Now we should start if all the commands are registered, even if they
    # are registered by two distincts plugins.
    del l1.daemon.opts["plugin"]
    l1.daemon.opts["plugin-dir"] = os.path.join(os.getcwd(),
                                                "tests/plugins/bitcoin/")
    # (it fails when it tries to use them, so startup fails)
    l1.daemon.start(wait_for_initialized=False)
    l1.daemon.wait_for_log("All Bitcoin plugin commands registered")
    assert l1.daemon.wait() == 1

    # But restarting with just bcli is ok
    del l1.daemon.opts["plugin-dir"]
    del l1.daemon.opts["disable-plugin"]
    l1.start()
    assert l1.daemon.is_in_log("bitcoin-cli initialized and connected to"
                               " bitcoind")


def test_bitcoin_bad_estimatefee(node_factory, bitcoind):
    """
    This tests that we don't crash if bitcoind backend gives bad estimatefees.
    """
    plugin = os.path.join(os.getcwd(), "tests/plugins/badestimate.py")
    l1 = node_factory.get_node(options={"disable-plugin": "bcli",
                                        "plugin": plugin,
                                        "badestimate-badorder": True},
                               start=False,
                               may_fail=True, allow_broken_log=True)
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert l1.daemon.wait() == 1
    l1.daemon.is_in_stderr(r"badestimate.py error: bad response to estimatefees.feerates \(Blocks must be ascending order: 2 <= 100!\)")

    del l1.daemon.opts["badestimate-badorder"]
    l1.start()

    l2 = node_factory.get_node(options={"disable-plugin": "bcli",
                                        "plugin": plugin})
    # Give me some funds.
    bitcoind.generate_block(5)
    l1.fundwallet(100 * 10**8)
    l1.connect(l2)
    l1.rpc.fundchannel(l2.info["id"], 50 * 10**8)


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
    assert 'feerate_floor' in estimates
    assert [f['blocks'] for f in estimates['feerates']] == [2, 6, 12, 100]

    resp = l1.rpc.call("getchaininfo", {"last_height": 0})
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


@unittest.skipIf(TEST_NETWORK != 'regtest', 'p2tr addresses not supported by elementsd')
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

    # For simplicity, give us N UTXOs to spend.
    addr = l1.rpc.newaddr('p2tr')['p2tr']
    for n in nodes:
        bitcoind.rpc.sendtoaddress(addr, (FUNDAMOUNT + 5000) / 10**8)
    bitcoind.generate_block(1, wait_for_mempool=len(nodes))
    sync_blockheight(bitcoind, [l1])

    # Start them in any order and we should still always end up with each
    # plugin being called and ultimately the `pay` call should succeed:
    for plugins, n in zip(perm, nodes):
        for p in plugins:
            n.rpc.plugin_start(p)
        l1.connect(n)
        l1.rpc.fundchannel(n.info['id'], FUNDAMOUNT)

    # Mine txs first.
    mine_funding_to_announce(bitcoind, [l1] + nodes, num_blocks=6, wait_for_mempool=len(nodes))

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2 * len(nodes))

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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_feature_set(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/show_feature_set.py')
    l1 = node_factory.get_node(options={"plugin": plugin})

    fs = l1.rpc.call('getfeatureset')

    assert fs['init'] == expected_peer_features()
    assert fs['node'] == expected_node_features()
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

    assert l2.daemon.wait_for_log("Attempt to pay.*with wrong secret")


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
    channel_id = l1.rpc.listpeerchannels()['channels'][0]['channel_id']

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
    lastcommitnum = 0
    for l in open(wt_file, 'r'):
        txid, penalty, channel_id_hook, commitnum = l.strip().split(', ')
        assert lastcommitnum == int(commitnum)
        assert channel_id_hook == channel_id
        lastcommitnum += 1
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
    # Can happen *before* the 'Server started with public key'
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log(r': exited during normal operation')

    l1.rpc.plugin_start(plugin)
    time.sleep(2)
    # It should clean up!
    assert 'failcmd' not in [h['command'] for h in l1.rpc.help()['help']]
    l1.daemon.wait_for_log(r': exited during normal operation')


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_coin_movement_notices(node_factory, bitcoind, chainparams):
    """Verify that channel coin movements are triggered correctly.  """

    l1_l2_mvts = [
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 0, 'tags': ['channel_open']},
        {'type': 'channel_mvt', 'credit_msat': 100001001, 'debit_msat': 0, 'tags': ['routed'], 'fees_msat': '1001msat'},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 50000000, 'tags': ['routed'], 'fees_msat': '501msat'},
        {'type': 'channel_mvt', 'credit_msat': 100000000, 'debit_msat': 0, 'tags': ['invoice'], 'fees_msat': '0msat'},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 50000000, 'tags': ['invoice'], 'fees_msat': '0msat'},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 100001001, 'tags': ['channel_close']},
    ]

    l2_l3_mvts = [
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 100000000, 'tags': ['routed'], 'fees_msat': '1001msat'},
        {'type': 'channel_mvt', 'credit_msat': 50000501, 'debit_msat': 0, 'tags': ['routed'], 'fees_msat': '501msat'},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 950000501, 'tags': ['channel_close']},
    ]

    l3_l2_mvts = [
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 0, 'tags': ['channel_open']},
        {'type': 'channel_mvt', 'credit_msat': 100000000, 'debit_msat': 0, 'tags': ['invoice'], 'fees_msat': '0msat'},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 50000501, 'tags': ['invoice'], 'fees_msat': '501msat'},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 49999499, 'tags': ['channel_close']},
    ]

    coin_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1, l2, l3 = node_factory.line_graph(3, opts=[
        {'may_reconnect': True},
        {'may_reconnect': True, 'plugin': coin_plugin},
        {'may_reconnect': True, 'plugin': coin_plugin},
    ], wait_for_announce=True)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)
    amount = 10**8

    inv = l3.rpc.invoice(amount, "first", "desc")
    payment_hash13 = inv['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    # status: offered -> settled
    l1.rpc.sendpay(route, payment_hash13, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(payment_hash13)

    # status: offered -> failed
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']
    payment_hash13 = "f" * 64
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash13, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash13)

    # go the other direction
    inv = l1.rpc.invoice(amount // 2, "first", "desc")
    payment_hash31 = inv['payment_hash']
    route = l3.rpc.getroute(l1.info['id'], amount // 2, 1)['route']
    l3.rpc.sendpay(route, payment_hash31, payment_secret=inv['payment_secret'])
    l3.rpc.waitsendpay(payment_hash31)

    # receive a payment (endpoint)
    inv = l2.rpc.invoice(amount, "first", "desc")
    payment_hash12 = inv['payment_hash']
    route = l1.rpc.getroute(l2.info['id'], amount, 1)['route']
    l1.rpc.sendpay(route, payment_hash12, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(payment_hash12)

    # send a payment (originator)
    inv = l1.rpc.invoice(amount // 2, "second", "desc")
    payment_hash21 = inv['payment_hash']
    # Make sure previous completely settled
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['htlcs'] == [])
    route = l2.rpc.getroute(l1.info['id'], amount // 2, 1)['route']
    l2.rpc.sendpay(route, payment_hash21, payment_secret=inv['payment_secret'])
    l2.rpc.waitsendpay(payment_hash21)

    # restart to test index
    l2.restart()
    wait_for(lambda: all(c['state'] == 'CHANNELD_NORMAL' for c in l2.rpc.listpeerchannels()["channels"]))

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
    l3.daemon.wait_for_log('Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by MUTUAL_CLOSE')

    # Ending channel balance should be zero
    assert account_balance(l2, chanid_1) == 0
    assert account_balance(l2, chanid_3) == 0

    # Verify we recorded all the movements we expect
    check_coin_moves(l3, chanid_3, l3_l2_mvts, chainparams)
    check_coin_moves(l2, chanid_1, l1_l2_mvts, chainparams)
    check_coin_moves(l2, chanid_3, l2_l3_mvts, chainparams)


def test_important_plugin(node_factory):
    # Cache it here.
    pluginsdir = os.path.join(os.path.dirname(__file__), "plugins")

    n = node_factory.get_node(options={"important-plugin": os.path.join(pluginsdir, "nonexistent")},
                              may_fail=True, expect_fail=True,
                              allow_broken_log=True, start=False)

    n.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert n.daemon.wait() == 1
    assert n.daemon.is_in_stderr(r"Failed to register .*nonexistent: No such file or directory")

    # Check we exit if the important plugin dies.
    n.daemon.opts['important-plugin'] = os.path.join(pluginsdir, "fail_by_itself.py")

    n.daemon.start(wait_for_initialized=False)
    # Will exit with failure code.
    assert n.daemon.wait() == 1
    n.daemon.wait_for_log(r'fail_by_itself.py: Plugin marked as important, shutting down lightningd')

    # Check if the important plugin is disabled, we run as normal.
    n.daemon.opts['disable-plugin'] = "fail_by_itself.py"
    n.daemon.start()
    # Make sure we can call into a plugin RPC (this is from `bcli`) even
    # if fail_by_itself.py is disabled.
    n.rpc.call("estimatefees", {})
    n.stop()

    # Check if an important plugin dies later, we fail.
    del n.daemon.opts['disable-plugin']
    n.daemon.opts['important-plugin'] = os.path.join(pluginsdir, "suicidal_plugin.py")

    n.start()

    with pytest.raises(RpcError):
        n.rpc.call("die", {})

    # Should exit with exitcode 1
    n.daemon.wait_for_log('suicidal_plugin.py: Plugin marked as important, shutting down lightningd')
    assert n.daemon.wait() == 1
    n.stop()

    # Check that if a builtin plugin dies, we fail.
    start = n.daemon.logsearch_start
    n.start()
    # Reset logsearch_start, since this will predate message that start() looks for.
    n.daemon.logsearch_start = start
    line = n.daemon.wait_for_log(r'.*started\([0-9]*\).*plugins/pay')
    pidstr = re.search(r'.*started\(([0-9]*)\).*plugins/pay', line).group(1)

    # Kill pay.
    os.kill(int(pidstr), signal.SIGKILL)
    n.daemon.wait_for_log('pay: Plugin marked as important, shutting down lightningd')
    # Should exit with exitcode 1
    assert n.daemon.wait() == 1
    n.stop()


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


@pytest.mark.skip("With newer GCC versions reports a '*** buffer overflow detected ***: terminated'")
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


def test_htlc_accepted_hook_fwdto(node_factory):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/htlc_accepted-fwdto.py')
    l1, l2, l3 = node_factory.line_graph(3, opts=[{}, {'plugin': plugin}, {}], wait_for_announce=True)

    # Add some balance
    l1.rpc.pay(l2.rpc.invoice(10**9 // 2, 'balance', '')['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # make it forward back down same channel.
    l2.rpc.setfwdto(only_one(l1.rpc.listpeerchannels()['channels'])['channel_id'])
    inv = l3.rpc.invoice(42, 'fwdto', '')['bolt11']
    with pytest.raises(RpcError, match="WIRE_INVALID_ONION_HMAC"):
        l1.rpc.pay(inv)

    assert l2.rpc.listforwards()['forwards'][0]['out_channel'] == only_one(l1.rpc.listpeerchannels()['channels'])['short_channel_id']


def test_dynamic_args(node_factory):
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')

    l1 = node_factory.get_node()
    l1.rpc.plugin_start(plugin_path, greeting='Test arg parsing')

    assert l1.rpc.call("hello") == "Test arg parsing world"
    assert l1.rpc.listconfigs('greeting')['configs']['greeting']['value_str'] == 'Test arg parsing'
    assert l1.rpc.listconfigs('greeting')['configs']['greeting']['plugin'] == plugin_path

    l1.rpc.plugin_stop(plugin_path)
    assert 'greeting' not in l1.rpc.listconfigs()['configs']


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

    pydisable = os.path.join(
        os.path.dirname(__file__), 'plugins/selfdisable.py'
    )
    l1 = node_factory.get_node(options={'important-plugin': [p1, p2],
                                        'plugin': pydisable,
                                        'selfdisable': None})

    # Could happen before it gets set up.
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs(['test_selfdisable_after_getmanifest: .* disabled itself: Self-disable test after getmanifest',
                             'test_libplugin: .* disabled itself at init: Disabled via selfdisable option',
                             'selfdisable.py: .* disabled itself at init: init saying disable'])

    assert p1 not in [p['name'] for p in l1.rpc.plugin_list()['plugins']]
    assert p2 not in [p['name'] for p in l1.rpc.plugin_list()['plugins']]
    assert pydisable not in [p['name'] for p in l1.rpc.plugin_list()['plugins']]

    # Also works with dynamic load attempts
    with pytest.raises(RpcError, match="Self-disable test after getmanifest"):
        l1.rpc.plugin_start(p1)

    # Also works with dynamic load attempts
    with pytest.raises(RpcError, match="Disabled via selfdisable option"):
        l1.rpc.plugin_start(p2, selfdisable=True)


def test_custom_notification_topics(node_factory):
    plugin = os.path.join(
        os.path.dirname(__file__), "plugins", "custom_notifications.py"
    )
    l1, l2 = node_factory.line_graph(2, opts=[{'plugin': plugin}, {}])
    l1.rpc.emit()
    l1.daemon.wait_for_log(r'Got a custom notification Hello world')

    inv = l2.rpc.invoice(42, "lbl", "desc")['bolt11']
    l1.rpc.pay(inv)

    l1.daemon.wait_for_log(r'Got a pay_success notification from plugin pay for payment_hash [0-9a-f]{64}')

    # And now make sure that we drop unannounced notifications
    l1.rpc.faulty_emit()
    l1.daemon.wait_for_log(
        r"Plugin attempted to send a notification to topic .* not forwarding"
    )
    time.sleep(1)
    assert not l1.daemon.is_in_log(r'Got the ididntannouncethis event')

    # The plugin just dist what previously was a fatal mistake (emit
    # an unknown notification), make sure we didn't kill it.
    assert str(plugin) in [p['name'] for p in l1.rpc.plugin_list()['plugins']]


def test_restart_on_update(node_factory):
    """Tests if plugin rescan restarts modified plugins
    """
    # we need to write plugin content dynamically
    content = """#!/usr/bin/env python3
from pyln.client import Plugin
import time
plugin = Plugin()
@plugin.init()
def init(options, configuration, plugin):
    plugin.log("test_restart_on_update %s")
plugin.run()
    """

    # get a node that is not started so we can put a plugin in its lightning_dir
    n = node_factory.get_node(start=False)
    if "dev-no-plugin-checksum" in n.daemon.opts:
        del n.daemon.opts["dev-no-plugin-checksum"]

    lndir = n.daemon.lightning_dir

    # write hello world plugin to lndir/plugins
    os.makedirs(os.path.join(lndir, 'plugins'), exist_ok=True)
    path = os.path.join(lndir, 'plugins', 'test_restart_on_update.py')
    file = open(path, 'w+')
    file.write(content % "1")
    file.close()
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    # now fire up the node and wait for the plugin to print hello
    n.daemon.start()
    n.daemon.logsearch_start = 0
    n.daemon.wait_for_log(r"test_restart_on_update 1")

    # a rescan should not yet reload the plugin on the same file
    n.rpc.plugin_rescan()
    assert not n.daemon.is_in_log(r"Plugin changed, needs restart.")

    # modify the file
    file = open(path, 'w+')
    file.write(content % "2")
    file.close()
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    # rescan and check
    n.rpc.plugin_rescan()
    n.daemon.wait_for_log(r"Plugin changed, needs restart.")
    n.daemon.wait_for_log(r"test_restart_on_update 2")
    n.stop()


def test_plugin_shutdown(node_factory):
    """test 'shutdown' notifications, via `plugin stop` or via `stop`"""

    p = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    p2 = os.path.join(os.getcwd(), 'tests/plugins/misc_notifications.py')
    l1 = node_factory.get_node(options={'plugin': [p, p2]})

    l1.rpc.plugin_stop(p)
    l1.daemon.wait_for_log(r"test_libplugin: shutdown called")
    # FIXME: clean this up!
    l1.daemon.wait_for_log(r"test_libplugin: Killing plugin: exited during normal operation")

    # Via `plugin stop` it can make RPC calls before it (self-)terminates
    l1.rpc.plugin_stop(p2)
    l1.daemon.wait_for_log(r'misc_notifications.py: via plugin stop, datastore success')
    l1.rpc.plugin_start(p2)

    # Now try timeout via `plugin stop`
    l1.rpc.plugin_start(p, dont_shutdown=True)
    l1.rpc.plugin_stop(p)
    l1.daemon.wait_for_log(r"test_libplugin: shutdown called")
    l1.daemon.wait_for_log(r"test_libplugin: Timeout on shutdown: killing anyway")

    # Now, should also shutdown or timeout on finish, RPC calls then fail with error code -5
    l1.rpc.plugin_start(p, dont_shutdown=True)
    l1.rpc.stop()
    l1.daemon.wait_for_logs(['test_libplugin: shutdown called',
                             'misc_notifications.py: .* Connection refused',
                             'test_libplugin: failed to self-terminate in time, killing.'])


def test_commando(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, fundchannel=False,
                                     opts={'log-level': 'io'})

    rune = l1.rpc.commando_rune()['rune']

    # Bad rune fails
    with pytest.raises(RpcError, match="Not authorized: Not derived from master"):
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'rune': 'VXY4AAkrPyH2vzSvOHnI7PDVfS6O04bRQLUCIUFJD5Y9NjQmbWV0aG9kPWludm9pY2UmcmF0ZT0yMZ==',
                             'method': 'listpeers'})

    # This works
    res = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'listpeers'})
    assert len(res['peers']) == 1
    assert res['peers'][0]['id'] == l2.info['id']

    # Check JSON id is as expected (unfortunately pytest does not use a reliable name
    # for itself: with -k it calls itself `-c` here, instead of `pytest`).
    l2.daemon.wait_for_log(r'plugin-commando: "[^:/]*:commando#[0-9]*/cln:commando#[0-9]*"\[OUT\]')
    l1.daemon.wait_for_log(r'jsonrpc#[0-9]*: "[^:/]*:commando#[0-9]*/cln:commando#[0-9]*/commando:listpeers#[0-9]*"\[IN\]')

    res = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'listpeers',
                               'params': {'id': l2.info['id']}})
    assert len(res['peers']) == 1
    assert res['peers'][0]['id'] == l2.info['id']

    # Filter test
    res = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'listpeers',
                               'filter': {'peers': [{'id': True}]}})
    assert res == {'peers': [{'id': l2.info['id']}]}

    with pytest.raises(RpcError, match='missing required parameter'):
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'rune': rune,
                             'method': 'withdraw'})

    with pytest.raises(RpcError, match='unknown parameter: foobar'):
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'method': 'invoice',
                             'rune': rune,
                             'params': {'foobar': 1}})

    ret = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'ping',
                               'params': {'id': l2.info['id']}})
    assert 'totlen' in ret

    # Now, reply will go over a multiple messages!
    ret = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'getlog',
                               'params': {'level': 'io'}})

    assert len(json.dumps(ret)) > 65535

    # Command will go over multiple messages.
    ret = l2.rpc.call(method='commando',
                      payload={'peer_id': l1.info['id'],
                               'rune': rune,
                               'method': 'invoice',
                               'params': {'amount_msat': 'any',
                                          'label': 'label',
                                          'description': 'A' * 200000,
                                          'deschashonly': True}})

    assert 'bolt11' in ret

    # This will fail, will include data.
    with pytest.raises(RpcError, match='No connection to first peer found') as exc_info:
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'rune': rune,
                             'method': 'sendpay',
                             'params': {'route': [{'amount_msat': 1000,
                                                   'id': l1.info['id'],
                                                   'delay': 12,
                                                   'channel': '1x2x3'}],
                                        'payment_hash': '00' * 32}})
    assert exc_info.value.error['data']['erring_index'] == 0


def test_commando_rune(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    rune1 = l1.rpc.commando_rune()
    assert rune1['rune'] == 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA=='
    assert rune1['unique_id'] == '0'
    rune2 = l1.rpc.commando_rune(restrictions="readonly")
    assert rune2['rune'] == 'zm0x_eLgHexaTvZn3Cz7gb_YlvrlYGDo_w4BYlR9SS09MSZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl'
    assert rune2['unique_id'] == '1'
    rune3 = l1.rpc.commando_rune(restrictions=[["time>1656675211"]])
    assert rune3['rune'] == 'mxHwVsC_W-PH7r79wXQWqxBNHaHncIqIjEPyP_vGOsE9MiZ0aW1lPjE2NTY2NzUyMTE='
    assert rune3['unique_id'] == '2'
    rune4 = l1.rpc.commando_rune(restrictions=[["id^022d223620a359a47ff7"], ["method=listpeers"]])
    assert rune4['rune'] == 'YPojv9qgHPa3im0eiqRb-g8aRq76OasyfltGGqdFUOU9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJz'
    assert rune4['unique_id'] == '3'
    rune5 = l1.rpc.commando_rune(rune4['rune'], [["pnamelevel!", "pnamelevel/io"]])
    assert rune5['rune'] == 'Zm7A2mKkLnd5l6Er_OMAHzGKba97ij8lA-MpNYMw9nk9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8='
    assert rune5['unique_id'] == '3'
    rune6 = l1.rpc.commando_rune(rune5['rune'], [["parr1!", "parr1/io"]])
    assert rune6['rune'] == 'm_tyR0qqHUuLEbFJW6AhmBg-9npxVX2yKocQBFi9cvY9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8mcGFycjEhfHBhcnIxL2lv'
    assert rune6['unique_id'] == '3'
    rune7 = l1.rpc.commando_rune(restrictions=[["pnum=0"]])
    assert rune7['rune'] == 'enX0sTpHB8y1ktyTAF80CnEvGetG340Ne3AGItudBS49NCZwbnVtPTA='
    assert rune7['unique_id'] == '4'
    rune8 = l1.rpc.commando_rune(rune7['rune'], [["rate=3"]])
    assert rune8['rune'] == '_h2eKjoK7ITAF-JQ1S5oum9oMQesrz-t1FR9kDChRB49NCZwbnVtPTAmcmF0ZT0z'
    assert rune8['unique_id'] == '4'
    rune9 = l1.rpc.commando_rune(rune8['rune'], [["rate=1"]])
    assert rune9['rune'] == 'U1GDXqXRvfN1A4WmDVETazU9YnvMsDyt7WwNzpY0khE9NCZwbnVtPTAmcmF0ZT0zJnJhdGU9MQ=='
    assert rune9['unique_id'] == '4'

    # Test rune with \|.
    weirdrune = l1.rpc.commando_rune(restrictions=[["method=invoice"],
                                                   ["pnamedescription=@tipjar|jb55@sendsats.lol"]])
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnamedescription is not equal to @tipjar|jb55@sendsats.lol'):
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'rune': weirdrune['rune'],
                             'method': 'invoice',
                             'params': {"amount_msat": "any",
                                        "label": "lbl",
                                        "description": "@tipjar\\|jb55@sendsats.lol"}})
    l2.rpc.call(method='commando',
                payload={'peer_id': l1.info['id'],
                         'rune': weirdrune['rune'],
                         'method': 'invoice',
                         'params': {"amount_msat": "any",
                                    "label": "lbl",
                                    "description": "@tipjar|jb55@sendsats.lol"}})

    runedecodes = ((rune1, []),
                   (rune2, [{'alternatives': ['method^list', 'method^get', 'method=summary'],
                             'summary': "method (of command) starts with 'list' OR method (of command) starts with 'get' OR method (of command) equal to 'summary'"},
                            {'alternatives': ['method/listdatastore'],
                             'summary': "method (of command) unequal to 'listdatastore'"}]),
                   (rune4, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"}]),
                   (rune5, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"},
                            {'alternatives': ['pnamelevel!', 'pnamelevel/io'],
                             'summary': "pnamelevel (object parameter 'level') is missing OR pnamelevel (object parameter 'level') unequal to 'io'"}]),
                   (rune6, [{'alternatives': ['id^022d223620a359a47ff7'],
                             'summary': "id (of commanding peer) starts with '022d223620a359a47ff7'"},
                            {'alternatives': ['method=listpeers'],
                             'summary': "method (of command) equal to 'listpeers'"},
                            {'alternatives': ['pnamelevel!', 'pnamelevel/io'],
                             'summary': "pnamelevel (object parameter 'level') is missing OR pnamelevel (object parameter 'level') unequal to 'io'"},
                            {'alternatives': ['parr1!', 'parr1/io'],
                             'summary': "parr1 (array parameter #1) is missing OR parr1 (array parameter #1) unequal to 'io'"}]),
                   (rune7, [{'alternatives': ['pnum=0'],
                             'summary': "pnum (number of command parameters) equal to 0"}]))
    for decode in runedecodes:
        rune = decode[0]
        restrictions = decode[1]
        decoded = l1.rpc.decode(rune['rune'])
        assert decoded['type'] == 'rune'
        assert decoded['unique_id'] == rune['unique_id']
        assert decoded['valid'] is True
        assert decoded['restrictions'] == restrictions

    # Time handling is a bit special, since we annotate the timestamp with how far away it is.
    decoded = l1.rpc.decode(rune3['rune'])
    assert decoded['type'] == 'rune'
    assert decoded['unique_id'] == rune3['unique_id']
    assert decoded['valid'] is True
    assert len(decoded['restrictions']) == 1
    assert decoded['restrictions'][0]['alternatives'] == ['time>1656675211']
    assert decoded['restrictions'][0]['summary'].startswith("time (in seconds since 1970) greater than 1656675211 (")

    # Replace rune3 with a more useful timestamp!
    expiry = int(time.time()) + 15
    rune3 = l1.rpc.commando_rune(restrictions=[["time<{}".format(expiry)]])

    successes = ((rune1, "listpeers", {}),
                 (rune2, "listpeers", {}),
                 (rune2, "getinfo", {}),
                 (rune2, "getinfo", {}),
                 (rune3, "getinfo", {}),
                 (rune4, "listpeers", {}),
                 (rune5, "listpeers", {'id': l2.info['id']}),
                 (rune5, "listpeers", {'id': l2.info['id'], 'level': 'broken'}),
                 (rune6, "listpeers", [l2.info['id'], 'broken']),
                 (rune6, "listpeers", [l2.info['id']]),
                 (rune7, "listpeers", []),
                 (rune7, "getinfo", {}))

    failures = ((rune2, "withdraw", {}),
                (rune2, "plugin", {'subcommand': 'list'}),
                (rune3, "getinfo", {}),
                (rune4, "listnodes", {}),
                (rune5, "listpeers", {'id': l2.info['id'], 'level': 'io'}),
                (rune6, "listpeers", [l2.info['id'], 'io']),
                (rune7, "listpeers", [l2.info['id']]),
                (rune7, "listpeers", {'id': l2.info['id']}))

    for rune, cmd, params in successes:
        l2.rpc.call(method='commando',
                    payload={'peer_id': l1.info['id'],
                             'rune': rune['rune'],
                             'method': cmd,
                             'params': params})

    while time.time() < expiry:
        time.sleep(1)

    for rune, cmd, params in failures:
        with pytest.raises(RpcError, match='Invalid rune: Not permitted:') as exc_info:
            l2.rpc.call(method='commando',
                        payload={'peer_id': l1.info['id'],
                                 'rune': rune['rune'],
                                 'method': cmd,
                                 'params': params})
        assert exc_info.value.error['code'] == 0x4c51


def test_commando_listrunes(node_factory):
    l1 = node_factory.get_node()
    rune = l1.rpc.commando_rune()
    assert rune == {
        'rune': 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==',
        'unique_id': '0',
        'warning_unrestricted_rune': 'WARNING: This rune has no restrictions! Anyone who has access to this rune could drain funds from your node. Be careful when giving this to apps that you don\'t trust. Consider using the restrictions parameter to only allow access to specific rpc methods.'
    }
    listrunes = l1.rpc.commando_listrunes()
    assert len(l1.rpc.commando_listrunes()) == 1
    rune = l1.rpc.commando_rune()
    listrunes = l1.rpc.commando_listrunes()
    assert len(listrunes['runes']) == 2
    assert listrunes == {
        'runes': [
            {
                'rune': 'OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==',
                'unique_id': '0',
                'restrictions': [],
                'restrictions_as_english': ''
            },
            {
                'rune': 'geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==',
                'unique_id': '1',
                'restrictions': [],
                'restrictions_as_english': ''
            }
        ]
    }
    our_unstored_rune = l1.rpc.commando_listrunes(rune='M8f4jNx9gSP2QoiRbr10ybwzFxUgd-rS4CR4yofMSuA9Mg==')['runes'][0]
    assert our_unstored_rune['stored'] is False

    our_unstored_rune = l1.rpc.commando_listrunes(rune='m_tyR0qqHUuLEbFJW6AhmBg-9npxVX2yKocQBFi9cvY9MyZpZF4wMjJkMjIzNjIwYTM1OWE0N2ZmNyZtZXRob2Q9bGlzdHBlZXJzJnBuYW1lbGV2ZWwhfHBuYW1lbGV2ZWwvaW8mcGFycjEhfHBhcnIxL2lv')['runes'][0]
    assert our_unstored_rune['stored'] is False

    not_our_rune = l1.rpc.commando_listrunes(rune='Am3W_wI0PRn4qVNEsJ2iInHyFPQK8wfdqEXztm8-icQ9MA==')['runes'][0]
    assert not_our_rune['stored'] is False
    assert not_our_rune['our_rune'] is False


def test_commando_rune_pay_amount(node_factory):
    l1, l2 = node_factory.line_graph(2)

    # This doesn't really work, since amount_msat is illegal if invoice
    # includes an amount, and runes aren't smart enough to decode bolt11!
    rune = l1.rpc.commando_rune(restrictions=[['method=pay'],
                                              ['pnameamountmsat<10000']])['rune']
    inv1 = l2.rpc.invoice(amount_msat=12300, label='inv1', description='description1')['bolt11']
    inv2 = l2.rpc.invoice(amount_msat='any', label='inv2', description='description2')['bolt11']

    # Rune requires amount_msat!
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnameamountmsat is not an integer field'):
        l2.rpc.commando(peer_id=l1.info['id'],
                        rune=rune,
                        method='pay',
                        params={'bolt11': inv1})

    # As a named parameter!
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnameamountmsat is not an integer field'):
        l2.rpc.commando(peer_id=l1.info['id'],
                        rune=rune,
                        method='pay',
                        params=[inv1])

    # Can't get around it this way!
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnameamountmsat is not an integer field'):
        l2.rpc.commando(peer_id=l1.info['id'],
                        rune=rune,
                        method='pay',
                        params=[inv2, 12000])

    # Nor this way, using a string!
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnameamountmsat is not an integer field'):
        l2.rpc.commando(peer_id=l1.info['id'],
                        rune=rune,
                        method='pay',
                        params={'bolt11': inv2, 'amount_msat': '10000sat'})

    # Too much!
    with pytest.raises(RpcError, match='Invalid rune: Not permitted: pnameamountmsat is greater or equal to 10000'):
        l2.rpc.commando(peer_id=l1.info['id'],
                        rune=rune,
                        method='pay',
                        params={'bolt11': inv2, 'amount_msat': 12000})

    # This works
    l2.rpc.commando(peer_id=l1.info['id'],
                    rune=rune,
                    method='pay',
                    params={'bolt11': inv2, 'amount_msat': 9999})


def test_commando_blacklist(node_factory):
    l1, l2 = node_factory.get_nodes(2)

    l2.connect(l1)
    rune0 = l1.rpc.commando_rune()
    assert rune0['unique_id'] == '0'
    rune1 = l1.rpc.commando_rune()
    assert rune1['unique_id'] == '1'

    # Make sure runes work!
    assert l2.rpc.call(method='commando',
                       payload={'peer_id': l1.info['id'],
                                'rune': rune0['rune'],
                                'method': 'getinfo',
                                'params': []})['id'] == l1.info['id']

    assert l2.rpc.call(method='commando',
                       payload={'peer_id': l1.info['id'],
                                'rune': rune1['rune'],
                                'method': 'getinfo',
                                'params': []})['id'] == l1.info['id']

    blacklist = l1.rpc.commando_blacklist(start=1)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 1}]}

    # Make sure rune id 1 does not work!
    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune'):
        assert l2.rpc.call(method='commando',
                           payload={'peer_id': l1.info['id'],
                                    'rune': rune1['rune'],
                                    'method': 'getinfo',
                                    'params': []})['id'] == l1.info['id']

    # But, other rune still works!
    assert l2.rpc.call(method='commando',
                       payload={'peer_id': l1.info['id'],
                                'rune': rune0['rune'],
                                'method': 'getinfo',
                                'params': []})['id'] == l1.info['id']

    blacklist = l1.rpc.commando_blacklist(start=2)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 2}]}

    blacklist = l1.rpc.commando_blacklist(start=6)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 2},
                                       {'start': 6, 'end': 6}]}

    blacklist = l1.rpc.commando_blacklist(start=3, end=5)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 6}]}

    blacklist = l1.rpc.commando_blacklist(start=9)
    assert blacklist == {'blacklist': [{'start': 1, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    blacklist = l1.rpc.commando_blacklist(start=0)
    assert blacklist == {'blacklist': [{'start': 0, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    # Now both runes fail!
    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune'):
        assert l2.rpc.call(method='commando',
                           payload={'peer_id': l1.info['id'],
                                    'rune': rune0['rune'],
                                    'method': 'getinfo',
                                    'params': []})['id'] == l1.info['id']

    with pytest.raises(RpcError, match='Not authorized: Blacklisted rune'):
        assert l2.rpc.call(method='commando',
                           payload={'peer_id': l1.info['id'],
                                    'rune': rune1['rune'],
                                    'method': 'getinfo',
                                    'params': []})['id'] == l1.info['id']

    blacklist = l1.rpc.commando_blacklist()
    assert blacklist == {'blacklist': [{'start': 0, 'end': 6},
                                       {'start': 9, 'end': 9}]}

    blacklisted_rune = l1.rpc.commando_listrunes(rune='geZmO6U7yqpHn-moaX93FVMVWrDRfSNY4AXx9ypLcqg9MQ==')['runes'][0]['blacklisted']
    assert blacklisted_rune is True


@pytest.mark.slow_test
def test_commando_stress(node_factory, executor):
    """Stress test to slam commando with many large queries"""
    nodes = node_factory.get_nodes(5)

    rune = nodes[0].rpc.commando_rune()['rune']
    for n in nodes[1:]:
        n.connect(nodes[0])

    futs = []
    for i in range(1000):
        node = random.choice(nodes[1:])
        futs.append(executor.submit(node.rpc.call, method='commando',
                                    payload={'peer_id': nodes[0].info['id'],
                                             'rune': rune,
                                             'method': 'invoice',
                                             'params': {'amount_msat': 'any',
                                                        'label': 'label{}'.format(i),
                                                        'description': 'A' * 200000,
                                                        'deschashonly': True}}))
    discards = 0
    for f in futs:
        try:
            f.result(TIMEOUT)
        except RpcError as e:
            assert(e.error['code'] == 0x4c50)
            assert(e.error['message'] == "Invalid JSON")
            discards += 1

    # Should have at least one discard msg from each failure (we can have
    # more, if they kept replacing each other, as happens!)
    if discards > 0:
        nodes[0].daemon.wait_for_logs([r"New cmd from .*, replacing old"] * discards)
    else:
        assert not nodes[0].daemon.is_in_log(r"New cmd from .*, replacing old")


def test_commando_badrune(node_factory):
    """Test invalid UTF-8 encodings in rune: used to make us kill the offers plugin which implements decode, as it gave bad utf8!"""
    l1 = node_factory.get_node()
    l1.rpc.decode('5zi6-ugA6hC4_XZ0R7snl5IuiQX4ugL4gm9BQKYaKUU9gCZtZXRob2RebGlzdHxtZXRob2ReZ2V0fG1ldGhvZD1zdW1tYXJ5Jm1ldGhvZC9saXN0ZGF0YXN0b3Jl')
    rune = l1.rpc.commando_rune(restrictions="readonly")

    binrune = base64.urlsafe_b64decode(rune['rune'])
    # Mangle each part, try decode.  Skip most of the boring chars
    # (just '|', '&', '#').
    for i in range(32, len(binrune)):
        for span in (range(0, 32), (124, 38, 35), range(127, 256)):
            for c in span:
                modrune = binrune[:i] + bytes([c]) + binrune[i + 1:]
                try:
                    l1.rpc.decode(base64.urlsafe_b64encode(modrune).decode('utf8'))
                except RpcError:
                    pass


def test_autoclean(node_factory):
    l1, l2, l3 = node_factory.line_graph(3, opts={'may_reconnect': True},
                                         wait_for_announce=True)

    # Under valgrind in CI, it can 50 seconds between creating invoice
    # and restarting.
    if node_factory.valgrind:
        short_timeout = 10
        longer_timeout = 60
    else:
        short_timeout = 5
        longer_timeout = 20

    assert l3.rpc.autoclean_status('expiredinvoices')['autoclean']['expiredinvoices']['enabled'] is False
    l3.rpc.invoice(amount_msat=12300, label='inv1', description='description1', expiry=short_timeout)
    l3.rpc.invoice(amount_msat=12300, label='inv2', description='description2', expiry=longer_timeout)
    l3.rpc.invoice(amount_msat=12300, label='inv3', description='description3', expiry=longer_timeout)
    inv4 = l3.rpc.invoice(amount_msat=12300, label='inv4', description='description4', expiry=2000)
    inv5 = l3.rpc.invoice(amount_msat=12300, label='inv5', description='description5', expiry=2000)

    # It must be an integer!
    with pytest.raises(RpcError, match=r'is not a number'):
        l3.rpc.setconfig('autoclean-expiredinvoices-age', 'xxx')

    l3.rpc.setconfig('autoclean-expiredinvoices-age', 2)
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['enabled'] is True
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['age'] == 2

    # Both should still be there.
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['cleaned'] == 0
    assert len(l3.rpc.listinvoices('inv1')['invoices']) == 1
    assert len(l3.rpc.listinvoices('inv2')['invoices']) == 1
    assert l3.rpc.listinvoices('inv1')['invoices'][0]['description'] == 'description1'

    l3.rpc.setconfig('autoclean-cycle', 10)

    # It will always go unpaid->expired->deleted, but we might miss it!
    was_expired = False
    while True:
        # Is it deleted yet?
        invs = l3.rpc.listinvoices('inv1')['invoices']
        if invs == []:
            break
        if was_expired:
            assert only_one(invs)['status'] == 'expired'
        else:
            if only_one(invs)['status'] == 'expired':
                was_expired = True
            else:
                assert only_one(invs)['status'] == 'unpaid'
        time.sleep(1)

    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['cleaned'] == 1

    # Keeps settings across restarts
    l3.restart()

    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['enabled'] is True
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['age'] == 2
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['cleaned'] == 1

    # Disabling works
    l3.rpc.setconfig('autoclean-expiredinvoices-age', 0)
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['enabled'] is False
    assert 'age' not in l3.rpc.autoclean_status()['autoclean']['expiredinvoices']

    # Same with inv2/3
    wait_for(lambda: only_one(l3.rpc.listinvoices('inv2')['invoices'])['status'] == 'expired')
    wait_for(lambda: only_one(l3.rpc.listinvoices('inv3')['invoices'])['status'] == 'expired')

    # Give it time to notice (runs every 10 seconds, give it 15)
    time.sleep(15)

    # They're still there!
    assert l3.rpc.listinvoices('inv2')['invoices'] != []
    assert l3.rpc.listinvoices('inv3')['invoices'] != []

    # Restart keeps it disabled.
    l3.restart()
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['enabled'] is False
    assert 'age' not in l3.rpc.autoclean_status()['autoclean']['expiredinvoices']

    # Now enable: they will get autocleaned
    l3.rpc.setconfig('autoclean-expiredinvoices-age', 2)
    wait_for(lambda: len(l3.rpc.listinvoices()['invoices']) == 2)
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['cleaned'] == 3

    # Reconnect, l1 pays invoice, we test paid expiry.
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.pay(inv4['bolt11'])

    # We manually delete inv5 so we can have l1 fail a payment.
    l3.rpc.delinvoice('inv5', 'unpaid')
    with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        l1.rpc.pay(inv5['bolt11'])

    assert l3.rpc.autoclean_status()['autoclean']['paidinvoices']['enabled'] is False
    assert l3.rpc.autoclean_status()['autoclean']['paidinvoices']['cleaned'] == 0
    l3.rpc.setconfig('autoclean-paidinvoices-age', 1)
    assert l3.rpc.autoclean_status()['autoclean']['paidinvoices']['enabled'] is True

    wait_for(lambda: l3.rpc.listinvoices()['invoices'] == [])
    assert l3.rpc.autoclean_status()['autoclean']['expiredinvoices']['cleaned'] == 3
    assert l3.rpc.autoclean_status()['autoclean']['paidinvoices']['cleaned'] == 1

    assert only_one(l1.rpc.listpays(inv5['bolt11'])['pays'])['status'] == 'failed'
    assert only_one(l1.rpc.listpays(inv4['bolt11'])['pays'])['status'] == 'complete'
    l1.rpc.setconfig('autoclean-failedpays-age', 1)
    l1.rpc.setconfig('autoclean-cycle', 5)

    wait_for(lambda: l1.rpc.listpays(inv5['bolt11'])['pays'] == [])
    assert l1.rpc.autoclean_status()['autoclean']['failedpays']['cleaned'] == 1
    assert l1.rpc.autoclean_status()['autoclean']['succeededpays']['cleaned'] == 0

    l1.rpc.setconfig('autoclean-succeededpays-age', 2)
    wait_for(lambda: l1.rpc.listpays(inv4['bolt11'])['pays'] == [])
    assert l1.rpc.listsendpays() == {'payments': []}

    # Now, we should have 1 failed forward, 1 success.
    assert len(l2.rpc.listforwards(status='failed')['forwards']) == 1
    assert len(l2.rpc.listforwards(status='settled')['forwards']) == 1
    assert len(l2.rpc.listforwards()['forwards']) == 2

    # Clean failed ones.
    l2.rpc.setconfig('autoclean-cycle', 5)
    l2.rpc.setconfig('autoclean-failedforwards-age', 2)
    wait_for(lambda: l2.rpc.listforwards(status='failed')['forwards'] == [])

    assert len(l2.rpc.listforwards(status='settled')['forwards']) == 1
    assert l2.rpc.autoclean_status()['autoclean']['failedforwards']['cleaned'] == 1
    assert l2.rpc.autoclean_status()['autoclean']['succeededforwards']['cleaned'] == 0

    amt_before = l2.rpc.getinfo()['fees_collected_msat']

    # Clean succeeded ones
    l2.rpc.setconfig('autoclean-succeededforwards-age', 2)
    wait_for(lambda: l2.rpc.listforwards(status='settled')['forwards'] == [])
    assert l2.rpc.listforwards() == {'forwards': []}
    assert l2.rpc.autoclean_status()['autoclean']['failedforwards']['cleaned'] == 1
    assert l2.rpc.autoclean_status()['autoclean']['succeededforwards']['cleaned'] == 1

    # We still see correct total in getinfo!
    assert l2.rpc.getinfo()['fees_collected_msat'] == amt_before


def test_autoclean_timer_crash(node_factory):
    """Running two autocleans at once crashed timer code"""
    node_factory.get_node(options={'autoclean-cycle': 1,
                                   'autoclean-failedforwards-age': 31536000,
                                   'autoclean-expiredinvoices-age': 31536000})
    time.sleep(20)


def test_autoclean_once(node_factory):
    l1, l2, l3 = node_factory.line_graph(3, opts={'may_reconnect': True},
                                         wait_for_announce=True)

    l3.rpc.invoice(amount_msat=12300, label='inv1', description='description1', expiry=1)
    inv2 = l3.rpc.invoice(amount_msat=12300, label='inv2', description='description4')
    inv3 = l3.rpc.invoice(amount_msat=12300, label='inv3', description='description5')

    l1.rpc.pay(inv2['bolt11'])
    l3.rpc.delinvoice('inv3', 'unpaid')
    with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        l1.rpc.pay(inv3['bolt11'])

    # Make sure > 1 second old!
    time.sleep(2)
    assert (l1.rpc.autoclean_once('failedpays', 1)
            == {'autoclean': {'failedpays': {'cleaned': 1, 'uncleaned': 1}}})
    assert l1.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 1},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 0},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 0},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 0},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 0},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 0}}}
    assert (l1.rpc.autoclean_once('succeededpays', 1)
            == {'autoclean': {'succeededpays': {'cleaned': 1, 'uncleaned': 0}}})
    assert l1.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 1},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 1},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 0},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 0},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 0},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 0}}}
    assert (l2.rpc.autoclean_once('failedforwards', 1)
            == {'autoclean': {'failedforwards': {'cleaned': 1, 'uncleaned': 1}}})
    assert l2.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 0},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 0},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 1},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 0},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 0},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 0}}}
    assert (l2.rpc.autoclean_once('succeededforwards', 1)
            == {'autoclean': {'succeededforwards': {'cleaned': 1, 'uncleaned': 0}}})
    assert l2.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 0},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 0},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 1},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 1},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 0},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 0}}}
    assert (l3.rpc.autoclean_once('expiredinvoices', 1)
            == {'autoclean': {'expiredinvoices': {'cleaned': 1, 'uncleaned': 1}}})
    assert l3.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 0},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 0},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 0},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 0},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 1},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 0}}}
    assert (l3.rpc.autoclean_once('paidinvoices', 1)
            == {'autoclean': {'paidinvoices': {'cleaned': 1, 'uncleaned': 0}}})
    assert l3.rpc.autoclean_status() == {'autoclean': {'failedpays': {'enabled': False,
                                                                      'cleaned': 0},
                                                       'succeededpays': {'enabled': False,
                                                                         'cleaned': 0},
                                                       'failedforwards': {'enabled': False,
                                                                          'cleaned': 0},
                                                       'succeededforwards': {'enabled': False,
                                                                             'cleaned': 0},
                                                       'expiredinvoices': {'enabled': False,
                                                                           'cleaned': 1},
                                                       'paidinvoices': {'enabled': False,
                                                                        'cleaned': 1}}}


def test_block_added_notifications(node_factory, bitcoind):
    """Test if a plugin gets notifications when a new block is found"""
    base = bitcoind.rpc.getblockchaininfo()["blocks"]
    plugin = [
        os.path.join(os.getcwd(), "tests/plugins/block_added.py"),
    ]
    l1 = node_factory.get_node(options={"plugin": plugin})
    ret = l1.rpc.call("blockscatched")
    assert len(ret) == 1 and ret[0] == base + 0

    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l1])
    ret = l1.rpc.call("blockscatched")
    assert len(ret) == 3 and ret[0] == base + 0 and ret[2] == base + 2

    l2 = node_factory.get_node(options={"plugin": plugin})
    ret = l2.rpc.call("blockscatched")
    assert len(ret) == 1 and ret[0] == base + 2

    l2.stop()
    next_l2_base = bitcoind.rpc.getblockchaininfo()["blocks"]

    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l1])
    ret = l1.rpc.call("blockscatched")
    assert len(ret) == 5 and ret[4] == base + 4

    l2.start()
    sync_blockheight(bitcoind, [l2])
    ret = l2.rpc.call("blockscatched")
    assert len(ret) == 3 and ret[1] == next_l2_base + 1 and ret[2] == next_l2_base + 2


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_sql(node_factory, bitcoind):
    opts = {'experimental-offers': None,
            'experimental-dual-fund': None,
            'dev-allow-localhost': None,
            'may_reconnect': True}
    l2opts = {'lease-fee-basis': 50,
              'experimental-dual-fund': None,
              'lease-fee-base-sat': '2000msat',
              'channel-fee-max-base-msat': '500sat',
              'channel-fee-max-proportional-thousandths': 200,
              'dev-sqlfilename': 'sql.sqlite3',
              'may_reconnect': True}
    l2opts.update(opts)
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[opts, l2opts, opts])

    ret = l2.rpc.sql("SELECT * FROM forwards;")
    assert ret == {'rows': []}

    # Test that we correctly clean up subtables!
    assert len(l2.rpc.sql("SELECT * from peerchannels_features")['rows']) == len(l2.rpc.sql("SELECT * from peerchannels_features")['rows'])

    expected_schemas = {
        'channels': {
            'indices': [['short_channel_id']],
            'columns': [{'name': 'source',
                         'type': 'pubkey'},
                        {'name': 'destination',
                         'type': 'pubkey'},
                        {'name': 'short_channel_id',
                         'type': 'short_channel_id'},
                        {'name': 'direction',
                         'type': 'u32'},
                        {'name': 'public',
                         'type': 'boolean'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'message_flags',
                         'type': 'u8'},
                        {'name': 'channel_flags',
                         'type': 'u8'},
                        {'name': 'active',
                         'type': 'boolean'},
                        {'name': 'last_update',
                         'type': 'u32'},
                        {'name': 'base_fee_millisatoshi',
                         'type': 'u32'},
                        {'name': 'fee_per_millionth',
                         'type': 'u32'},
                        {'name': 'delay',
                         'type': 'u32'},
                        {'name': 'htlc_minimum_msat',
                         'type': 'msat'},
                        {'name': 'htlc_maximum_msat',
                         'type': 'msat'},
                        {'name': 'features',
                         'type': 'hex'}]},
        'closedchannels': {
            'columns': [{'name': 'peer_id',
                         'type': 'pubkey'},
                        {'name': 'channel_id',
                         'type': 'hash'},
                        {'name': 'short_channel_id',
                         'type': 'short_channel_id'},
                        {'name': 'alias_local',
                         'type': 'short_channel_id'},
                        {'name': 'alias_remote',
                         'type': 'short_channel_id'},
                        {'name': 'opener',
                         'type': 'string'},
                        {'name': 'closer',
                         'type': 'string'},
                        {'name': 'private',
                         'type': 'boolean'},
                        {'name': 'total_local_commitments',
                         'type': 'u64'},
                        {'name': 'total_remote_commitments',
                         'type': 'u64'},
                        {'name': 'total_htlcs_sent',
                         'type': 'u64'},
                        {'name': 'funding_txid',
                         'type': 'txid'},
                        {'name': 'funding_outnum',
                         'type': 'u32'},
                        {'name': 'leased',
                         'type': 'boolean'},
                        {'name': 'funding_fee_paid_msat',
                         'type': 'msat'},
                        {'name': 'funding_fee_rcvd_msat',
                         'type': 'msat'},
                        {'name': 'funding_pushed_msat',
                         'type': 'msat'},
                        {'name': 'total_msat',
                         'type': 'msat'},
                        {'name': 'final_to_us_msat',
                         'type': 'msat'},
                        {'name': 'min_to_us_msat',
                         'type': 'msat'},
                        {'name': 'max_to_us_msat',
                         'type': 'msat'},
                        {'name': 'last_commitment_txid',
                         'type': 'txid'},
                        {'name': 'last_commitment_fee_msat',
                         'type': 'msat'},
                        {'name': 'close_cause',
                         'type': 'string'}]},
        'closedchannels_channel_type_bits': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'bits',
                         'type': 'u64'}]},
        'closedchannels_channel_type_names': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'names',
                         'type': 'string'}]},
        'nodes': {
            'indices': [['nodeid']],
            'columns': [{'name': 'nodeid',
                         'type': 'pubkey'},
                        {'name': 'last_timestamp',
                         'type': 'u32'},
                        {'name': 'alias',
                         'type': 'string'},
                        {'name': 'color',
                         'type': 'hex'},
                        {'name': 'features',
                         'type': 'hex'},
                        {'name': 'option_will_fund_lease_fee_base_msat',
                         'type': 'msat'},
                        {'name': 'option_will_fund_lease_fee_basis',
                         'type': 'u32'},
                        {'name': 'option_will_fund_funding_weight',
                         'type': 'u32'},
                        {'name': 'option_will_fund_channel_fee_max_base_msat',
                         'type': 'msat'},
                        {'name': 'option_will_fund_channel_fee_max_proportional_thousandths',
                         'type': 'u32'},
                        {'name': 'option_will_fund_compact_lease',
                         'type': 'hex'},
                        ]},
        'nodes_addresses': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'type',
                         'type': 'string'},
                        {'name': 'port',
                         'type': 'u16'},
                        {'name': 'address',
                         'type': 'string'}]},
        'forwards': {
            'indices': [['in_channel', 'in_htlc_id']],
            'columns': [{'name': 'created_index',
                         'type': 'u64'},
                        {'name': 'in_channel',
                         'type': 'short_channel_id'},
                        {'name': 'in_htlc_id',
                         'type': 'u64'},
                        {'name': 'in_msat',
                         'type': 'msat'},
                        {'name': 'status',
                         'type': 'string'},
                        {'name': 'received_time',
                         'type': 'number'},
                        {'name': 'out_channel',
                         'type': 'short_channel_id'},
                        {'name': 'out_htlc_id',
                         'type': 'u64'},
                        {'name': 'updated_index',
                         'type': 'u64'},
                        {'name': 'style',
                         'type': 'string'},
                        {'name': 'fee_msat',
                         'type': 'msat'},
                        {'name': 'out_msat',
                         'type': 'msat'},
                        {'name': 'resolved_time',
                         'type': 'number'},
                        {'name': 'failcode',
                         'type': 'u32'},
                        {'name': 'failreason',
                         'type': 'string'}]},
        'htlcs': {
            'indices': [['short_channel_id', 'id']],
            'columns': [{'name': 'short_channel_id',
                         'type': 'short_channel_id'},
                        {'name': 'id',
                         'type': 'u64'},
                        {'name': 'expiry',
                         'type': 'u32'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'direction',
                         'type': 'string'},
                        {'name': 'payment_hash',
                         'type': 'hash'},
                        {'name': 'state',
                         'type': 'string'}]},
        'invoices': {
            'indices': [['payment_hash']],
            'columns': [{'name': 'label',
                         'type': 'string'},
                        {'name': 'description',
                         'type': 'string'},
                        {'name': 'payment_hash',
                         'type': 'hash'},
                        {'name': 'status',
                         'type': 'string'},
                        {'name': 'expires_at',
                         'type': 'u64'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'bolt11',
                         'type': 'string'},
                        {'name': 'bolt12',
                         'type': 'string'},
                        {'name': 'local_offer_id',
                         'type': 'hex'},
                        {'name': 'invreq_payer_note',
                         'type': 'string'},
                        {'name': 'created_index',
                         'type': 'u64'},
                        {'name': 'updated_index',
                         'type': 'u64'},
                        {'name': 'pay_index',
                         'type': 'u64'},
                        {'name': 'amount_received_msat',
                         'type': 'msat'},
                        {'name': 'paid_at',
                         'type': 'u64'},
                        {'name': 'paid_outpoint_txid',
                         'type': 'txid'},
                        {'name': 'paid_outpoint_outnum',
                         'type': 'u32'},
                        {'name': 'payment_preimage',
                         'type': 'secret'}]},
        'offers': {
            'indices': [['offer_id']],
            'columns': [{'name': 'offer_id',
                         'type': 'hex'},
                        {'name': 'active',
                         'type': 'boolean'},
                        {'name': 'single_use',
                         'type': 'boolean'},
                        {'name': 'bolt12',
                         'type': 'string'},
                        {'name': 'used',
                         'type': 'boolean'},
                        {'name': 'label',
                         'type': 'string'}]},
        'peers': {
            'indices': [['id']],
            'columns': [{'name': 'id',
                         'type': 'pubkey'},
                        {'name': 'connected',
                         'type': 'boolean'},
                        {'name': 'num_channels',
                         'type': 'u32'},
                        {'name': 'remote_addr',
                         'type': 'string'},
                        {'name': 'features',
                         'type': 'hex'}]},
        'peers_netaddr': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'netaddr',
                         'type': 'string'}]},
        'sendpays': {
            'indices': [['payment_hash']],
            'columns': [{'name': 'created_index',
                         'type': 'u64'},
                        {'name': 'id',
                         'type': 'u64'},
                        {'name': 'groupid',
                         'type': 'u64'},
                        {'name': 'partid',
                         'type': 'u64'},
                        {'name': 'payment_hash',
                         'type': 'hash'},
                        {'name': 'updated_index',
                         'type': 'u64'},
                        {'name': 'status',
                         'type': 'string'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'destination',
                         'type': 'pubkey'},
                        {'name': 'created_at',
                         'type': 'u64'},
                        {'name': 'amount_sent_msat',
                         'type': 'msat'},
                        {'name': 'label',
                         'type': 'string'},
                        {'name': 'bolt11',
                         'type': 'string'},
                        {'name': 'description',
                         'type': 'string'},
                        {'name': 'bolt12',
                         'type': 'string'},
                        {'name': 'payment_preimage',
                         'type': 'secret'},
                        {'name': 'erroronion',
                         'type': 'hex'}]},
        'peerchannels': {
            'indices': [['peer_id']],
            'columns': [{'name': 'peer_id',
                         'type': 'pubkey'},
                        {'name': 'peer_connected',
                         'type': 'boolean'},
                        {'name': 'state',
                         'type': 'string'},
                        {'name': 'scratch_txid',
                         'type': 'txid'},
                        {'name': 'local_htlc_minimum_msat',
                         'type': 'msat'},
                        {'name': 'local_htlc_maximum_msat',
                         'type': 'msat'},
                        {'name': 'local_cltv_expiry_delta',
                         'type': 'u32'},
                        {'name': 'local_fee_base_msat',
                         'type': 'msat'},
                        {'name': 'local_fee_proportional_millionths',
                         'type': 'u32'},
                        {'name': 'remote_htlc_minimum_msat',
                         'type': 'msat'},
                        {'name': 'remote_htlc_maximum_msat',
                         'type': 'msat'},
                        {'name': 'remote_cltv_expiry_delta',
                         'type': 'u32'},
                        {'name': 'remote_fee_base_msat',
                         'type': 'msat'},
                        {'name': 'remote_fee_proportional_millionths',
                         'type': 'u32'},
                        {'name': 'ignore_fee_limits',
                         'type': 'boolean'},
                        {'name': 'feerate_perkw',
                         'type': 'u32'},
                        {'name': 'feerate_perkb',
                         'type': 'u32'},
                        {'name': 'owner',
                         'type': 'string'},
                        {'name': 'short_channel_id',
                         'type': 'short_channel_id'},
                        {'name': 'channel_id',
                         'type': 'hash'},
                        {'name': 'funding_txid',
                         'type': 'txid'},
                        {'name': 'funding_outnum',
                         'type': 'u32'},
                        {'name': 'initial_feerate',
                         'type': 'string'},
                        {'name': 'last_feerate',
                         'type': 'string'},
                        {'name': 'next_feerate',
                         'type': 'string'},
                        {'name': 'next_fee_step',
                         'type': 'u32'},
                        {'name': 'close_to',
                         'type': 'hex'},
                        {'name': 'private',
                         'type': 'boolean'},
                        {'name': 'opener',
                         'type': 'string'},
                        {'name': 'closer',
                         'type': 'string'},
                        {'name': 'funding_pushed_msat',
                         'type': 'msat'},
                        {'name': 'funding_local_funds_msat',
                         'type': 'msat'},
                        {'name': 'funding_remote_funds_msat',
                         'type': 'msat'},
                        {'name': 'funding_fee_paid_msat',
                         'type': 'msat'},
                        {'name': 'funding_fee_rcvd_msat',
                         'type': 'msat'},
                        {'name': 'to_us_msat',
                         'type': 'msat'},
                        {'name': 'min_to_us_msat',
                         'type': 'msat'},
                        {'name': 'max_to_us_msat',
                         'type': 'msat'},
                        {'name': 'total_msat',
                         'type': 'msat'},
                        {'name': 'fee_base_msat',
                         'type': 'msat'},
                        {'name': 'fee_proportional_millionths',
                         'type': 'u32'},
                        {'name': 'dust_limit_msat',
                         'type': 'msat'},
                        {'name': 'max_total_htlc_in_msat',
                         'type': 'msat'},
                        {'name': 'their_reserve_msat',
                         'type': 'msat'},
                        {'name': 'our_reserve_msat',
                         'type': 'msat'},
                        {'name': 'spendable_msat',
                         'type': 'msat'},
                        {'name': 'receivable_msat',
                         'type': 'msat'},
                        {'name': 'minimum_htlc_in_msat',
                         'type': 'msat'},
                        {'name': 'minimum_htlc_out_msat',
                         'type': 'msat'},
                        {'name': 'maximum_htlc_out_msat',
                         'type': 'msat'},
                        {'name': 'their_to_self_delay',
                         'type': 'u32'},
                        {'name': 'our_to_self_delay',
                         'type': 'u32'},
                        {'name': 'max_accepted_htlcs',
                         'type': 'u32'},
                        {'name': 'alias_local',
                         'type': 'short_channel_id'},
                        {'name': 'alias_remote',
                         'type': 'short_channel_id'},
                        {'name': 'in_payments_offered',
                         'type': 'u64'},
                        {'name': 'in_offered_msat',
                         'type': 'msat'},
                        {'name': 'in_payments_fulfilled',
                         'type': 'u64'},
                        {'name': 'in_fulfilled_msat',
                         'type': 'msat'},
                        {'name': 'out_payments_offered',
                         'type': 'u64'},
                        {'name': 'out_offered_msat',
                         'type': 'msat'},
                        {'name': 'out_payments_fulfilled',
                         'type': 'u64'},
                        {'name': 'out_fulfilled_msat',
                         'type': 'msat'},
                        {'name': 'reestablished',
                         'type': 'boolean'},
                        {'name': 'close_to_addr',
                         'type': 'string'},
                        {'name': 'last_tx_fee_msat',
                         'type': 'msat'},
                        {'name': 'direction',
                         'type': 'u32'}]},
        'peerchannels_features': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'features',
                         'type': 'string'}]},
        'peerchannels_htlcs': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'direction',
                         'type': 'string'},
                        {'name': 'id',
                         'type': 'u64'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'expiry',
                         'type': 'u32'},
                        {'name': 'payment_hash',
                         'type': 'hash'},
                        {'name': 'local_trimmed',
                         'type': 'boolean'},
                        {'name': 'status',
                         'type': 'string'},
                        {'name': 'state',
                         'type': 'string'}]},
        'peerchannels_inflight': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'funding_txid',
                         'type': 'txid'},
                        {'name': 'funding_outnum',
                         'type': 'u32'},
                        {'name': 'feerate',
                         'type': 'string'},
                        {'name': 'total_funding_msat',
                         'type': 'msat'},
                        {'name': 'splice_amount',
                         'type': 's64'},
                        {'name': 'our_funding_msat',
                         'type': 'msat'},
                        {'name': 'scratch_txid',
                         'type': 'txid'}]},
        'peerchannels_status': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'status',
                         'type': 'string'}]},
        'peerchannels_state_changes': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'timestamp',
                         'type': 'string'},
                        {'name': 'old_state',
                         'type': 'string'},
                        {'name': 'new_state',
                         'type': 'string'},
                        {'name': 'cause',
                         'type': 'string'},
                        {'name': 'message',
                         'type': 'string'}]},
        'peerchannels_channel_type_bits': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'bits',
                         'type': 'u64'}]},
        'peerchannels_channel_type_names': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'names',
                         'type': 'string'}]},
        'transactions': {
            'indices': [['hash']],
            'columns': [{'name': 'hash',
                         'type': 'txid'},
                        {'name': 'rawtx',
                         'type': 'hex'},
                        {'name': 'blockheight',
                         'type': 'u32'},
                        {'name': 'txindex',
                         'type': 'u32'},
                        {'name': 'locktime',
                         'type': 'u32'},
                        {'name': 'version',
                         'type': 'u32'}]},
        'transactions_inputs': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'txid',
                         'type': 'hex'},
                        {'name': 'idx',
                         'type': 'u32'},
                        {'name': 'sequence',
                         'type': 'u32'}]},
        'transactions_outputs': {
            'columns': [{'name': 'row',
                         'type': 'u64'},
                        {'name': 'arrindex',
                         'type': 'u64'},
                        {'name': 'idx',
                         'type': 'u32'},
                        {'name': 'amount_msat',
                         'type': 'msat'},
                        {'name': 'scriptPubKey',
                         'type': 'hex'}]},
        'bkpr_accountevents': {
            'columns': [{'name': 'account',
                         'type': 'string'},
                        {'name': 'type',
                         'type': 'string'},
                        {'name': 'tag',
                         'type': 'string'},
                        {'name': 'credit_msat',
                         'type': 'msat'},
                        {'name': 'debit_msat',
                         'type': 'msat'},
                        {'name': 'currency',
                         'type': 'string'},
                        {'name': 'timestamp',
                         'type': 'u32'},
                        {'name': 'outpoint',
                         'type': 'string'},
                        {'name': 'blockheight',
                         'type': 'u32'},
                        {'name': 'origin',
                         'type': 'string'},
                        {'name': 'payment_id',
                         'type': 'hex'},
                        {'name': 'txid',
                         'type': 'txid'},
                        {'name': 'description',
                         'type': 'string'},
                        {'name': 'fees_msat',
                         'type': 'msat'},
                        {'name': 'is_rebalance',
                         'type': 'boolean'},
                        {'name': 'part_id',
                         'type': 'u32'}]},
        'bkpr_income': {
            'columns': [{'name': 'account',
                         'type': 'string'},
                        {'name': 'tag',
                         'type': 'string'},
                        {'name': 'credit_msat',
                         'type': 'msat'},
                        {'name': 'debit_msat',
                         'type': 'msat'},
                        {'name': 'currency',
                         'type': 'string'},
                        {'name': 'timestamp',
                         'type': 'u32'},
                        {'name': 'description',
                         'type': 'string'},
                        {'name': 'outpoint',
                         'type': 'string'},
                        {'name': 'txid',
                         'type': 'txid'},
                        {'name': 'payment_id',
                         'type': 'hex'}]}}

    sqltypemap = {'string': 'TEXT',
                  'boolean': 'INTEGER',
                  'u8': 'INTEGER',
                  'u16': 'INTEGER',
                  'u32': 'INTEGER',
                  'u64': 'INTEGER',
                  's64': 'INTEGER',
                  'msat': 'INTEGER',
                  'hex': 'BLOB',
                  'hash': 'BLOB',
                  'txid': 'BLOB',
                  'pubkey': 'BLOB',
                  'secret': 'BLOB',
                  'number': 'REAL',
                  'short_channel_id': 'TEXT'}

    # Check schemas match (each one has rowid at start)
    rowidcol = {'name': 'rowid', 'type': 'u64'}
    for table, schema in expected_schemas.items():
        res = only_one(l2.rpc.listsqlschemas(table)['schemas'])
        assert res['tablename'] == table
        assert res.get('indices') == schema.get('indices')
        sqlcolumns = [{'name': c['name'], 'type': sqltypemap[c['type']]} for c in [rowidcol] + schema['columns']]
        assert res['columns'] == sqlcolumns

    # Make sure we didn't miss any
    assert (sorted([s['tablename'] for s in l1.rpc.listsqlschemas()['schemas']])
            == sorted(expected_schemas.keys()))
    assert len(l1.rpc.listsqlschemas()['schemas']) == len(expected_schemas)

    # We need one closed channel (but open a new one)
    l2.rpc.close(l1.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=1)
    scid, _ = l1.fundchannel(l2)
    # Completely forget old channel
    bitcoind.generate_block(99)
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels']) == 2)

    # Make sure l3 sees new channel
    wait_for(lambda: len(l3.rpc.listchannels(scid)['channels']) == 2)

    # This should create a forward through l2
    l1.rpc.pay(l3.rpc.invoice(amount_msat=12300, label='inv1', description='description')['bolt11'])

    # Very rough checks of other list commands (make sure l2 has one of each)
    l2.rpc.offer(1, 'desc')
    l2.rpc.invoice(1, 'label', 'desc')
    l2.rpc.pay(l3.rpc.invoice(amount_msat=12300, label='inv2', description='description')['bolt11'])

    # And I need at least one HTLC in-flight so listpeers.channels.htlcs isn't empty:
    l3.rpc.plugin_start(os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'),
                        holdtime=TIMEOUT * 2)
    inv = l3.rpc.invoice(amount_msat=12300, label='inv3', description='description')
    route = l1.rpc.getroute(l3.info['id'], 12300, 1)['route']
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    # And an in-flight channel open...
    l2.openchannel(l3, confirm=False, wait_for_announce=False)

    for table, schema in expected_schemas.items():
        ret = l2.rpc.sql("SELECT * FROM {};".format(table))
        assert len(ret['rows'][0]) == 1 + len(schema['columns'])

        # First column is always rowid!
        for row in ret['rows']:
            assert row[0] > 0

        for col in schema['columns']:
            val = only_one(l2.rpc.sql("SELECT {} FROM {};".format(col['name'], table))['rows'][0])
            # Could be null
            if val is None:
                continue
            if col['type'] == "hex":
                bytes.fromhex(val)
            elif col['type'] in ("hash", "secret", "txid"):
                assert len(bytes.fromhex(val)) == 32
            elif col['type'] == "pubkey":
                assert len(bytes.fromhex(val)) == 33
            elif col['type'] in ("msat", "integer", "s64", "u64", "u32", "u16", "u8", "boolean"):
                int(val)
            elif col['type'] == "number":
                float(val)
            elif col['type'] == "string":
                val += ""
            elif col['type'] == "short_channel_id":
                assert len(val.split('x')) == 3
            else:
                assert False

    ret = l2.rpc.sql("SELECT in_htlc_id,out_msat,status,out_htlc_id FROM forwards WHERE in_htlc_id = 0;")
    assert only_one(ret['rows']) == [0, 12300, 'settled', 0]

    with pytest.raises(RpcError, match='Unauthorized'):
        l2.rpc.sql("DELETE FROM forwards;")

    assert len(l3.rpc.sql("SELECT * FROM channels;")['rows']) == 4
    # Check that channels gets refreshed!
    scid = l1.get_channel_scid(l2)
    l1.rpc.setchannel(scid, feebase=123)
    wait_for(lambda: l3.rpc.sql("SELECT short_channel_id FROM channels WHERE base_fee_millisatoshi = 123;")['rows'] == [[scid]])
    l3.daemon.wait_for_log("Refreshing channels...")
    l3.daemon.wait_for_log("Refreshing channel: {}".format(scid))

    # This has to wait for the hold_invoice plugin to let go!
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(13, wait_for_mempool=txid)
    wait_for(lambda: len(l3.rpc.listchannels(source=l1.info['id'])['channels']) == 0)
    assert len(l3.rpc.sql("SELECT * FROM channels WHERE source = X'{}';".format(l1.info['id']))['rows']) == 0
    l3.daemon.wait_for_log("Deleting channel: {}".format(scid))

    # No deprecated fields!
    with pytest.raises(RpcError, match='query failed with no such column: funding_local_msat'):
        l2.rpc.sql("SELECT funding_local_msat FROM peerchannels;")

    with pytest.raises(RpcError, match='query failed with no such column: funding_remote_msat'):
        l2.rpc.sql("SELECT funding_remote_msat FROM peerchannels;")

    with pytest.raises(RpcError, match='query failed with no such table: peers_channels'):
        l2.rpc.sql("SELECT * FROM peers_channels;")

    # Test subobject case (option_will_fund)
    ret = l2.rpc.sql("SELECT option_will_fund_lease_fee_base_msat,"
                     " option_will_fund_lease_fee_basis,"
                     " option_will_fund_funding_weight,"
                     " option_will_fund_channel_fee_max_base_msat,"
                     " option_will_fund_channel_fee_max_proportional_thousandths,"
                     " option_will_fund_compact_lease"
                     " FROM nodes WHERE HEX(nodeid) = '{}';".format(l2.info['id'].upper()))
    optret = only_one(l2.rpc.listnodes(l2.info['id'])['nodes'])['option_will_fund']
    row = only_one(ret['rows'])
    assert row == [v for v in optret.values()]

    # Correctly handles missing object.
    assert l2.rpc.sql("SELECT option_will_fund_lease_fee_base_msat,"
                      " option_will_fund_lease_fee_basis,"
                      " option_will_fund_funding_weight,"
                      " option_will_fund_channel_fee_max_base_msat,"
                      " option_will_fund_channel_fee_max_proportional_thousandths,"
                      " option_will_fund_compact_lease"
                      " FROM nodes WHERE HEX(nodeid) = '{}';".format(l1.info['id'].upper())) == {'rows': [[None] * 6]}

    # Test that nodes get updated.
    l2.stop()
    l2.daemon.opts["alias"] = "TESTALIAS"
    # Don't try to reuse the same db file!
    del l2.daemon.opts["dev-sqlfilename"]
    l2.start()
    # DEV appends stuff to alias!
    alias = l2.rpc.getinfo()['alias']
    assert alias == "TESTALIAS"
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    wait_for(lambda: l3.rpc.sql("SELECT * FROM nodes WHERE alias = '{}'".format(alias))['rows'] != [])


def test_sql_deprecated(node_factory, bitcoind):
    # deprecated-apis breaks schemas...
    l1 = node_factory.get_node(start=False, options={'allow-deprecated-apis': True})
    l1.rpc.check_request_schemas = False
    l1.start()

    # FIXME: we have no fields which have been deprecated since sql plugin was
    # introduced.  When we do, add them here! (I manually tested a fake one)

    #  ret = l1.rpc.sql("SELECT funding_local_msat, funding_remote_msat FROM peerchannels;")
    #  assert ret == {'rows': []}


def test_plugin_persist_option(node_factory):
    """test that options from config file get remembered across plugin stop/start"""
    plugin_path = os.path.join(os.getcwd(), 'contrib/plugins/helloworld.py')

    l1 = node_factory.get_node(options={"plugin": plugin_path,
                                        "greeting": "Static option"})
    assert l1.rpc.call("hello") == "Static option world"
    c = l1.rpc.listconfigs('greeting')['configs']['greeting']
    assert c['source'] == "cmdline"
    assert c['value_str'] == "Static option"
    assert c['plugin'] == plugin_path
    l1.rpc.plugin_stop(plugin_path)
    assert 'greeting' not in l1.rpc.listconfigs()['configs']

    # Restart works
    l1.rpc.plugin_start(plugin_path)
    c = l1.rpc.listconfigs('greeting')['configs']['greeting']
    assert c['source'] == "cmdline"
    assert c['value_str'] == "Static option"
    assert c['plugin'] == plugin_path
    assert l1.rpc.call("hello") == "Static option world"
    l1.rpc.plugin_stop(plugin_path)
    assert 'greeting' not in l1.rpc.listconfigs()['configs']

    # This overrides!
    l1.rpc.plugin_start(plugin_path, greeting="Dynamic option")
    c = l1.rpc.listconfigs('greeting')['configs']['greeting']
    assert c['source'] == "pluginstart"
    assert c['value_str'] == "Dynamic option"
    assert c['plugin'] == plugin_path
    assert l1.rpc.call("hello") == "Dynamic option world"
    l1.rpc.plugin_stop(plugin_path)
    assert 'greeting' not in l1.rpc.listconfigs()['configs']

    # Now restored!
    l1.rpc.plugin_start(plugin_path)
    c = l1.rpc.listconfigs('greeting')['configs']['greeting']
    assert c['source'] == "cmdline"
    assert c['value_str'] == "Static option"
    assert c['plugin'] == plugin_path
    assert l1.rpc.call("hello") == "Static option world"


def test_all_subscription(node_factory, directory):
    """Ensure that registering for all notifications works."""
    plugin1 = os.path.join(os.getcwd(), 'tests/plugins/all_notifications.py')
    plugin2 = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")

    l1, l2 = node_factory.line_graph(2, opts=[{"plugin": plugin1},
                                              {"plugin": plugin2}])

    l1.stop()
    l2.stop()

    # There will be a lot of these!
    for notstr in ("block_added: {'block_added': {'hash': ",
                   "balance_snapshot: {'balance_snapshot': {'node_id': ",
                   "connect: {'connect': {'id': ",
                   "channel_state_changed: {'channel_state_changed': {'peer_id': ",
                   "shutdown: {'shutdown': {}"):
        assert l1.daemon.is_in_log(f".*plugin-all_notifications.py: notification {notstr}.*")

    for notstr in ('block_added: ',
                   'balance_snapshot: ',
                   'channel_state_changed: {'):
        assert l2.daemon.is_in_log(f'.*test_libplugin: all: {notstr}.*')

    # shutdown and connect are subscribed before the wildcard, so is handled by that handler
    assert not l2.daemon.is_in_log(f'.*test_libplugin: all: shutdown.*')
    assert not l2.daemon.is_in_log(f'.*test_libplugin: all: connect.*')


def test_dynamic_option_python_plugin(node_factory):
    plugin = os.path.join(os.getcwd(), "tests/plugins/dynamic_option.py")
    ln = node_factory.get_node(options={"plugin": plugin})
    result = ln.rpc.listconfigs("test-dynamic-config")

    assert result["configs"]["test-dynamic-config"]["value_str"] == "initial"

    result = ln.rpc.setconfig("test-dynamic-config", "changed")
    assert result["config"]["value_str"] == "changed"


def test_renepay_not_important(node_factory):
    # I mean, it's *important*, it's just not "mission-critical" just yet!
    l1 = node_factory.get_node(options={'allow-deprecated-apis': True})

    assert not any([p['name'] == 'cln-renepay' for p in l1.rpc.listconfigs()['important-plugins']])
    assert [p['name'] for p in l1.rpc.listconfigs()['plugins'] if p['name'] == 'cln-renepay'] == ['cln-renepay']

    # We can kill it without cln dying.
    line = l1.daemon.is_in_log(r'.*started\([0-9]*\).*plugins/cln-renepay')
    pidstr = re.search(r'.*started\(([0-9]*)\).*plugins/cln-renepay', line).group(1)
    os.kill(int(pidstr), signal.SIGKILL)
    l1.daemon.wait_for_log('plugin-cln-renepay: Killing plugin: exited during normal operation')

    # But we don't shut down, and we can restrart.
    assert [p['name'] for p in l1.rpc.listconfigs()['plugins'] if p['name'] == 'cln-renepay'] == []
    l1.rpc.plugin_start(os.path.join(os.getcwd(), 'plugins/cln-renepay'))


@unittest.skipIf(VALGRIND, "Valgrind doesn't handle bad #! lines the same")
def test_plugin_nostart(node_factory):
    "Should not appear in list if it didn't even start"

    l1 = node_factory.get_node()
    with pytest.raises(RpcError, match="badinterp.py: opening pipe: No such file or directory"):
        l1.rpc.plugin_start(os.path.join(os.getcwd(), 'tests/plugins/badinterp.py'))

    assert [p['name'] for p in l1.rpc.plugin_list()['plugins'] if 'badinterp' in p['name']] == []


@unittest.skip("A bit flaky, but when breaks, it is costing us 2h of CI time")
def test_plugin_startdir_lol(node_factory):
    """Though we fail to start many of them, we don't crash!"""
    l1 = node_factory.get_node(allow_broken_log=True)
    l1.rpc.plugin_startdir(os.path.join(os.getcwd(), 'tests/plugins'))
