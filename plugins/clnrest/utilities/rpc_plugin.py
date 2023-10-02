import os
from pyln.client import Plugin

plugin = Plugin(autopatch=False)

plugin.add_option(name="rest-certs", default=os.getcwd(), description="Path for certificates (for https)", opt_type="string", deprecated=False)
plugin.add_option(name="rest-protocol", default="https", description="REST server protocol", opt_type="string", deprecated=False)
plugin.add_option(name="rest-host", default="127.0.0.1", description="REST server host", opt_type="string", deprecated=False)
plugin.add_option(name="rest-port", default=None, description="REST server port to listen", opt_type="int", deprecated=False)
plugin.add_option(name="rest-cors-origins", default="*", description="Cross origin resource sharing origins", opt_type="string", deprecated=False, multi=True)
plugin.add_option(name="rest-csp", default="default-src 'self'; font-src 'self'; img-src 'self' data:; frame-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';", description="Content security policy (CSP) for the server", opt_type="string", deprecated=False, multi=False)
