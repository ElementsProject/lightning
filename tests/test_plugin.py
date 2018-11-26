from fixtures import *  # noqa: F401,F403
from lightning import RpcError

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
    n = node_factory.get_node(options={'plugin': plugin_path, 'greeting': 'Mars'})
    n.stop()


def test_rpc_passthrough(node_factory):
    """Starting with a plugin exposes its RPC methods.

    First check that the RPC method appears in the help output and
    then try to call it.

    """
    plugin_path = 'contrib/plugins/helloworld.py'
    n = node_factory.get_node(options={'plugin': plugin_path, 'greeting': 'Mars'})

    # Make sure that the 'hello' command that the helloworld.py plugin
    # has registered is available.
    cmd = [hlp for hlp in n.rpc.help()['help'] if 'hello' in hlp['command']]
    assert(len(cmd) == 1)

    # Now try to call it and see what it returns:
    greet = n.rpc.hello(name='Sun')
    assert(greet == "Hello Sun")
    with pytest.raises(RpcError):
        n.rpc.fail()
