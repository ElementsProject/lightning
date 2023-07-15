import os
from pyln.client import Plugin

plugin = Plugin(autopatch=False)

plugin.add_option(name="rest-certs", default=os.getcwd(), description="Path for certificates (for https)", opt_type="string", deprecated=False)
plugin.add_option(name="rest-protocol", default="https", description="REST server protocol", opt_type="string", deprecated=False)
plugin.add_option(name="rest-host", default="127.0.0.1", description="REST server host", opt_type="string", deprecated=False)
plugin.add_option(name="rest-port", default=None, description="REST server port to listen", opt_type="int", deprecated=False)
