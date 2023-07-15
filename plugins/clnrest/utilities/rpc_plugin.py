import os
import sys
from multiprocessing import Manager
from pyln.client import Plugin

plugin = Plugin(autopatch=False)
manager = Manager()
queue = manager.Queue()

plugin.add_option(name="rest-certs", default=os.getcwd(), description="Path for certificates (for https)", opt_type="string", deprecated=False)
plugin.add_option(name="rest-protocol", default="https", description="REST server protocol", opt_type="string", deprecated=False)
plugin.add_option(name="rest-host", default="127.0.0.1", description="REST server host", opt_type="string", deprecated=False)
plugin.add_option(name="rest-port", default=None, description="REST server port to listen", opt_type="int", deprecated=False)


@plugin.subscribe("*")
def on_any_notification(request, **kwargs):
    plugin.log("Notification: {}".format(kwargs), "debug")
    if request.method == 'shutdown':
        # A plugin which subscribes to shutdown is expected to exit itself.
        sys.exit(0)
    else:
        queue.put(str(kwargs) + "\n")
