from collections import OrderedDict
from fixtures import *  # noqa: F401,F403
from lightning import RpcError
from utils import only_one

import pytest
import subprocess


def test_option_passthrough(node_factory):
    """ Ensure that registering options works.

    First attempts without the plugin and then with the plugin.
    """
    plugin_path = 'contrib/plugins/helloworld.py'

    help_out = subprocess.check_output([
        'lightningd/lightningd',
        '--help'
    ]).decode('utf-8')
    assert('--greeting' not in help_out)

    help_out = subprocess.check_output([
        'lightningd/lightningd',
        '--plugin={}'.format(plugin_path),
        '--help'
    ]).decode('utf-8')
    assert('--greeting' in help_out)

    # Now try to see if it gets accepted, would fail to start if the
    # option didn't exist
    n = node_factory.get_node(options={'plugin': plugin_path, 'greeting': 'Ciao'})
    n.stop()


def test_rpc_passthrough(node_factory):
    """Starting with a plugin exposes its RPC methods.

    First check that the RPC method appears in the help output and
    then try to call it.

    """
    plugin_path = 'contrib/plugins/helloworld.py'
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
    plugin_dir = 'contrib/plugins'
    node_factory.get_node(options={'plugin-dir': plugin_dir, 'greeting': 'Mars'})


def test_plugin_disable(node_factory):
    """--disable-plugin works"""
    plugin_dir = 'contrib/plugins'
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


def test_plugin_notifications(node_factory):
    l1, l2 = node_factory.get_nodes(2, opts={'plugin': 'contrib/plugins/helloworld.py'})

    l1.connect(l2)
    l1.daemon.wait_for_log(r'Received connect event')
    l2.daemon.wait_for_log(r'Received connect event')

    l2.rpc.disconnect(l1.info['id'])
    l1.daemon.wait_for_log(r'Received disconnect event')
    l2.daemon.wait_for_log(r'Received disconnect event')


def test_failing_plugins():
    fail_plugins = [
        'contrib/plugins/fail/failtimeout.py',
        'contrib/plugins/fail/doesnotexist.py',
    ]

    for p in fail_plugins:
        with pytest.raises(subprocess.CalledProcessError):
            subprocess.check_output([
                'lightningd/lightningd',
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
    assert only_one(l1.rpc.help('pay')['help'])['command'] == 'pay bolt11 [msatoshi] [description] [riskfactor] [maxfeepercent] [retry_for] [maxdelay] [exemptfee]'
    assert only_one(l1.rpc.help('paystatus')['help'])['command'] == 'paystatus [bolt11]'


def test_plugin_connected_hook(node_factory):
    """ l1 uses the reject plugin to reject connections.

    l1 is configured to accept connections from l2, but not from l3.
    """
    opts = [{'plugin': 'tests/plugins/reject.py'}, {}, {}]
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    l1.rpc.reject(l3.info['id'])

    l2.connect(l1)
    l1.daemon.wait_for_log(r"{} is allowed".format(l2.info['id']))
    assert len(l1.rpc.listpeers(l2.info['id'])['peers']) == 1

    l3.connect(l1)
    l1.daemon.wait_for_log(r"{} is in reject list".format(l3.info['id']))

    peer = l1.rpc.listpeers(l3.info['id'])['peers']
    assert(peer == [] or not peer[0]['connected'])
