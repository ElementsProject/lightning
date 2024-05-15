from fixtures import *  # noqa: F401,F403
from pyln.testing.utils import env, TEST_NETWORK
from pyln.client import Millisatoshi
import unittest
import os
import requests
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socketio
import time


def http_session_with_retry():
    # All requests are done after matching "REST server running" in the log,
    # but there may be a 'small' lag between that message in the log and the
    # web server really available for incoming requests.  So we use an http
    # session to retry several times the requests.
    http_session = requests.Session()
    retry = Retry(connect=10, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    http_session.mount('https://', adapter)
    return http_session


def test_clnrest_no_auto_start(node_factory):
    """Ensure that we do not start clnrest unless a `clnrest-port` is configured."""
    l1 = node_factory.get_node()
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    assert [p for p in l1.rpc.plugin('list')['plugins'] if 'clnrest' in p['name']] == []
    assert l1.daemon.is_in_log(r'plugin-clnrest: Killing plugin: disabled itself at init: `clnrest-port` option is not configured')


def test_clnrest_self_signed_certificates(node_factory):
    """Test that self-signed certificates have `clnrest-host` IP in Subject Alternative Name."""
    rest_port = str(node_factory.get_unused_port())
    rest_host = '127.0.0.1'
    base_url = f'https://{rest_host}:{rest_port}'
    l1 = node_factory.get_node(options={'disable-plugin': 'cln-grpc',
                                        'clnrest-port': rest_port,
                                        'clnrest-host': rest_host})
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log(r'plugin-clnrest: REST server running at ' + base_url)
    ca_cert = Path(l1.daemon.lightning_dir) / TEST_NETWORK / 'ca.pem'

    http_session = http_session_with_retry()
    response = http_session.get(base_url + '/v1/list-methods', verify=ca_cert)
    assert response.status_code == 200


@unittest.skipIf(env('RUST') != '1', 'RUST is not enabled skipping rust-dependent tests')
def test_clnrest_uses_grpc_plugin_certificates(node_factory):
    """Test that clnrest reuses `cln-grpc` plugin certificates if available.
    Defaults:
    - clnrest-protocol: https
    """
    rest_host = 'localhost'
    grpc_port = str(node_factory.get_unused_port())
    rest_port = str(node_factory.get_unused_port())
    l1 = node_factory.get_node(options={'grpc-port': grpc_port, 'clnrest-host': rest_host, 'clnrest-port': rest_port})
    base_url = f'https://{rest_host}:{rest_port}'
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs([r'serving grpc on 0.0.0.0:',
                             r'plugin-clnrest: REST server running at ' + base_url])
    ca_cert = Path(l1.daemon.lightning_dir) / TEST_NETWORK / 'ca.pem'
    http_session = http_session_with_retry()
    response = http_session.get(base_url + '/v1/list-methods', verify=ca_cert)
    assert response.status_code == 200


def test_clnrest_generate_certificate(node_factory):
    """Test whether we correctly generate the certificates."""
    # when `clnrest-protocol` is `http`, certs are not generated at `clnrest-certs` path
    rest_port = str(node_factory.get_unused_port())
    rest_protocol = 'http'
    rest_certs = node_factory.directory + '/clnrest-certs'
    l1 = node_factory.get_node(options={'clnrest-port': rest_port,
                                        'clnrest-protocol': rest_protocol,
                                        'clnrest-certs': rest_certs})

    assert not Path(rest_certs).exists()

    # node l1 not started
    rest_port = str(node_factory.get_unused_port())
    rest_certs = node_factory.directory + '/clnrest-certs'
    l1 = node_factory.get_node(options={'clnrest-port': rest_port,
                                        'clnrest-certs': rest_certs}, start=False)
    rest_certs_path = Path(rest_certs)
    files = [rest_certs_path / f for f in [
        'ca.pem',
        'ca-key.pem',
        'client.pem',
        'client-key.pem',
        'server-key.pem',
        'server.pem',
    ]]

    # before starting no files exist.
    assert [f.exists() for f in files] == [False] * len(files)

    # certificates generated at startup
    l1.start()
    assert [f.exists() for f in files] == [True] * len(files)

    # the files exist, restarting should not change them
    contents = [f.open().read() for f in files]
    l1.restart()
    assert contents == [f.open().read() for f in files]

    # remove client.pem file, so all certs are regenerated at restart
    files[2].unlink()
    l1.restart()
    contents_1 = [f.open().read() for f in files]
    assert [c[0] != c[1] for c in zip(contents, contents_1)] == [True] * len(files)

    # remove client-key.pem file, so all certs are regenerated at restart
    files[3].unlink()
    l1.restart()
    contents_2 = [f.open().read() for f in files]
    assert [c[0] != c[1] for c in zip(contents, contents_2)] == [True] * len(files)


def start_node_with_clnrest(node_factory):
    """Start a node with the clnrest plugin, whose options are the default options.
    Return:
    - the node,
    - the base url and
    - the certificate authority path used for the self-signed certificates."""
    rest_port = str(node_factory.get_unused_port())
    rest_certs = node_factory.directory + '/clnrest-certs'
    l1 = node_factory.get_node(options={'clnrest-port': rest_port, 'clnrest-certs': rest_certs})
    base_url = 'https://127.0.0.1:' + rest_port
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log(r'plugin-clnrest: REST server running at ' + base_url)
    ca_cert = Path(rest_certs) / 'ca.pem'
    return l1, base_url, ca_cert


def test_clnrest_list_methods(node_factory):
    """Test GET request on `/v1/list-methods` end point with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # /v1/list-methods
    http_session = http_session_with_retry()
    response = http_session.get(base_url + '/v1/list-methods', verify=ca_cert)
    assert response.status_code == 200
    assert response.text.find('Command: getinfo') > 0


def test_clnrest_unknown_method(node_factory):
    """Test GET request error on `/v1/unknown-get` end point with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)
    http_session = http_session_with_retry()

    response = http_session.get(base_url + '/v1/unknown-get', verify=ca_cert)
    assert response.status_code == 405
    assert response.json()['message'] == 'The method is not allowed for the requested URL.'

    """Test POST request error on `/v1/unknown-post` end point."""
    rune = l1.rpc.createrune()['rune']
    response = http_session.post(base_url + '/v1/unknown-post', headers={'Rune': rune}, verify=ca_cert)
    assert response.status_code == 404
    assert response.json()['code'] == -32601
    assert response.json()['message'] == "Unknown command 'unknown-post'"


def test_clnrest_rpc_method(node_factory):
    """Test POST requests on `/v1/<rpc_method>` end points with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)
    http_session = http_session_with_retry()

    # /v1/getinfo no rune provided in header of the request
    response = http_session.post(base_url + '/v1/getinfo', verify=ca_cert)
    assert response.status_code == 403
    assert response.json()['code'] == 1501
    assert response.json()['message'] == 'Not authorized: Missing rune'

    # /v1/getinfo with a rune which doesn't authorized getinfo method
    rune_no_getinfo = l1.rpc.createrune(restrictions=[["method/getinfo"]])['rune']
    response = http_session.post(base_url + '/v1/getinfo', headers={'Rune': rune_no_getinfo},
                                 verify=ca_cert)
    assert response.status_code == 401
    assert response.json()['code'] == 1502
    assert response.json()['message'] == 'Not permitted: method is equal to getinfo'

    # /v1/getinfo with a correct rune
    rune_getinfo = l1.rpc.createrune(restrictions=[["method=getinfo"]])['rune']
    response = http_session.post(base_url + '/v1/getinfo', headers={'Rune': rune_getinfo},
                                 verify=ca_cert)
    assert response.status_code == 201
    assert response.json()['id'] == l1.info['id']

    # /v1/invoice with a correct rune but missing parameters
    rune_invoice = l1.rpc.createrune(restrictions=[["method=invoice"]])['rune']
    response = http_session.post(base_url + '/v1/invoice', headers={'Rune': rune_invoice},
                                 verify=ca_cert)
    assert response.status_code == 500
    assert response.json()['code'] == -32602

    # /v1/invoice with a correct rune but wrong parameters
    rune_invoice = l1.rpc.createrune(restrictions=[["method=invoice"]])['rune']
    response = http_session.post(base_url + '/v1/invoice', headers={'Rune': rune_invoice},
                                 data={'amount_msat': '<WRONG>',
                                       'label': 'label',
                                       'description': 'description'},
                                 verify=ca_cert)
    assert response.status_code == 500
    assert response.json()['code'] == -32602

    # l2 pays l1's invoice where the invoice is created with /v1/invoice
    rune_invoice = l1.rpc.createrune(restrictions=[["method=invoice"]])['rune']
    response = http_session.post(base_url + '/v1/invoice', headers={'Rune': rune_invoice},
                                 data={'amount_msat': '50000000',
                                       'label': 'label',
                                       'description': 'description'},
                                 verify=ca_cert)
    assert response.status_code == 201
    assert 'bolt11' in response.json()


def test_clnrest_large_response(node_factory):
    """Test a large reply still works (and msat fields are integers!)"""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)
    http_session = http_session_with_retry()

    # Add 500 invoices, test list
    NUM_INVOICES = 500
    for i in range(NUM_INVOICES):
        l1.rpc.invoice(amount_msat=100, label=str(i), description="inv")

    rune = l1.rpc.createrune()['rune']
    response = http_session.post(base_url + '/v1/listinvoices', headers={'Rune': rune},
                                 verify=ca_cert)
    # No, this doesn't return JSON, it *parses* it into a Python object!
    resp = response.json()

    # Make sure it hasn't turned msat fields into strings!
    assert not isinstance(resp['invoices'][0]['amount_msat'], Millisatoshi)
    assert len(resp['invoices']) == NUM_INVOICES


# Tests for websocket are written separately to avoid flake8
# to complain with the errors F811 like this "F811 redefinition of
# unused 'message'".

def notifications_received_via_websocket(l1, base_url, http_session, rpc_method='invoice', rpc_params=[100000, 'label', 'description']):
    """Return the list of notifications received by the websocket client.

    We try to connect to the websocket server running at `base_url`
    with `http_session` parameters.  Then we create an invoice on the node:

    - if we were effectively connected, we received an `invoice_creation`
      notification via websocket that should be in the list of notifications
      we return.
    - if we couldn't connect to the websocket server, the notification list
      we return is empty."""
    sio = socketio.Client(http_session=http_session)
    notifications = []

    @sio.event
    def message(data):
        notifications.append(data)
    sio.connect(base_url)
    time.sleep(2)
    # trigger notification by calling method
    rpc_call = getattr(l1.rpc, rpc_method)
    rpc_call(*rpc_params)
    time.sleep(2)
    sio.disconnect()
    return notifications


def test_clnrest_websocket_no_rune(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # no rune provided => no websocket connection and no notification received
    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    assert len(notifications) == 0


def test_clnrest_websocket_wrong_rune(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # wrong rune provided => no websocket connection and no notification received
    http_session.headers.update({"rune": "jMHrjVJb5l9-mjEd7zwux7Ookra1fgZ8wa9D8QbVT-w9MA=="})

    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    l1.daemon.logsearch_start = 0
    assert l1.daemon.is_in_log(r"error: {'code': 1501, 'message': 'Not authorized: Not derived from master'}")
    assert len(notifications) == 0


def test_clnrest_websocket_unrestricted_rune(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # unrestricted rune provided => websocket connection and notifications received
    rune_unrestricted = l1.rpc.createrune()['rune']
    http_session.headers.update({"rune": rune_unrestricted})
    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    assert len([n for n in notifications if not n.get('invoice_creation') is None]) == 1


def test_clnrest_websocket_rune_readonly(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # readonly rune provided => websocket connection and notifications received
    rune_readonly = l1.rpc.createrune(restrictions="readonly")['rune']
    http_session.headers.update({"rune": rune_readonly})
    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    assert len([n for n in notifications if not n.get('invoice_creation') is None]) == 1


def test_clnrest_websocket_rune_listnotifications(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # rune authorizing listclnrest-notifications method provided => websocket connection and notifications received
    rune_clnrest_notifications = l1.rpc.createrune(restrictions=[["method=listclnrest-notifications"]])['rune']
    http_session.headers.update({"rune": rune_clnrest_notifications})
    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    assert len([n for n in notifications if not n.get('invoice_creation') is None]) == 1


def test_clnrest_websocket_rune_no_listnotifications(node_factory):
    """Test websocket with default values for options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)

    # http session
    http_session = http_session_with_retry()
    http_session.verify = ca_cert.as_posix()

    # with a rune which doesn't authorized listclnrest-notifications method => no websocket connection and no notification received
    rune_no_clnrest_notifications = l1.rpc.createrune(restrictions=[["method/listclnrest-notifications"]])['rune']
    http_session.headers.update({"rune": rune_no_clnrest_notifications})
    notifications = notifications_received_via_websocket(l1, base_url, http_session)
    assert len([n for n in notifications if n.find('invoice_creation') > 0]) == 0


def test_clnrest_numeric_msat_notification(node_factory):
    """Test that msat fields are integers in notifications also."""
    # start a node with clnrest
    rest_port = str(node_factory.get_unused_port())
    base_url = 'http://127.0.0.1:' + rest_port
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {'clnrest-port': rest_port, 'clnrest-protocol': 'http'}])
    node_factory.join_nodes([l1, l2], wait_for_announce=True)
    http_session = http_session_with_retry()

    # create an invoice on l2
    inv = l2.rpc.invoice(5000000, 'test_invoice_payment_notification', 'test_invoice_payment_notification_description')

    # create rune authorizing listclnrest-notifications method
    rune_clnrest_notifications = l2.rpc.createrune(restrictions=[["method=listclnrest-notifications"]])['rune']
    http_session.headers.update({"rune": rune_clnrest_notifications})
    notifications = notifications_received_via_websocket(l1, base_url, http_session, 'pay', [inv['bolt11']])
    filtered_notifications = [n for n in notifications if 'invoice_creation' in n]

    assert isinstance(filtered_notifications[0]['invoice_creation']['msat'], int)
    assert filtered_notifications[0]['invoice_creation']['msat'] == 5000000


def test_clnrest_options(node_factory):
    """Test startup options `clnrest-host`, `clnrest-protocol` and `clnrest-certs`."""
    # with invalid port
    rest_port = 1000
    l1 = node_factory.get_node(options={'clnrest-port': rest_port})
    assert l1.daemon.is_in_log(f'plugin-clnrest: Killing plugin: disabled itself at init: `clnrest-port` {rest_port}, should be a valid available port between 1024 and 65535.')

    # with invalid protocol
    rest_port = str(node_factory.get_unused_port())
    rest_protocol = 'htttps'
    l1 = node_factory.get_node(options={'clnrest-port': rest_port,
                                        'clnrest-protocol': rest_protocol})
    assert l1.daemon.is_in_log(r'plugin-clnrest: Killing plugin: disabled itself at init: `clnrest-protocol` can either be http or https.')

    # with invalid host
    rest_port = str(node_factory.get_unused_port())
    rest_host = '127.0.0.12.15'
    l1 = node_factory.get_node(options={'clnrest-port': rest_port,
                                        'clnrest-host': rest_host})
    assert l1.daemon.is_in_log(r'plugin-clnrest: Killing plugin: disabled itself at init: `clnrest-host` should be a valid IP.')


def test_clnrest_http_headers(node_factory):
    """Test HTTP headers set with `clnrest-csp` and `clnrest-cors-origins` options."""
    # start a node with clnrest
    l1, base_url, ca_cert = start_node_with_clnrest(node_factory)
    http_session = http_session_with_retry()

    # Default values for `clnrest-csp` and `clnrest-cors-origins` options
    response = http_session.get(base_url + '/v1/list-methods', verify=ca_cert)
    assert response.headers['Content-Security-Policy'] == "default-src 'self'; font-src 'self'; img-src 'self' data:; frame-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';"
    assert response.headers['Access-Control-Allow-Origin'] == '*'
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log(f'plugin-clnrest: REST server running at {base_url}')

    # Custom values for `clnrest-csp` and `clnrest-cors-origins` options
    rest_port = str(node_factory.get_unused_port())
    rest_certs = node_factory.directory + '/clnrest-certs'
    l2 = node_factory.get_node(options={
        'clnrest-port': rest_port,
        'clnrest-certs': rest_certs,
        'clnrest-csp': "default-src 'self'; font-src 'self'; img-src 'self'; frame-src 'self'; style-src 'self'; script-src 'self';",
        'clnrest-cors-origins': ['https://localhost:5500', 'http://192.168.1.30:3030', 'http://192.168.1.10:1010']
    })
    base_url = 'https://127.0.0.1:' + rest_port
    # This might happen really early!
    l2.daemon.logsearch_start = 0
    l2.daemon.wait_for_log(f'plugin-clnrest: REST server running at {base_url}')
    ca_cert = Path(rest_certs) / 'ca.pem'

    response = http_session.get(base_url + '/v1/list-methods',
                                headers={'Origin': 'http://192.168.1.30:3030'},
                                verify=ca_cert)
    assert response.headers['Content-Security-Policy'] == "default-src 'self'; font-src 'self'; img-src 'self'; frame-src 'self'; style-src 'self'; script-src 'self';"
    assert response.headers['Access-Control-Allow-Origin'] == 'http://192.168.1.30:3030'
    response = http_session.get(base_url + '/v1/list-methods',
                                headers={'Origin': 'http://192.168.1.10:1010'},
                                verify=ca_cert)
    assert response.headers['Access-Control-Allow-Origin'] == 'http://192.168.1.10:1010'


def test_clnrest_old_params(node_factory):
    """Test that we handle the v23.08-style parameters"""
    rest_port = str(node_factory.get_unused_port())
    rest_host = '127.0.0.1'
    base_url = f'https://{rest_host}:{rest_port}'
    l1 = node_factory.get_node(options={'rest-port': rest_port,
                                        'rest-host': rest_host,
                                        'allow-deprecated-apis': True})
    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_logs([r'UNUSUAL lightningd: Option rest-port=.* deprecated in v23\.11, renaming to clnrest-port',
                             r'UNUSUAL lightningd: Option rest-host=.* deprecated in v23\.11, renaming to clnrest-host'])
    l1.daemon.wait_for_log(r'plugin-clnrest: REST server running at ' + base_url)

    # Now try one where a plugin (e.g. clightning-rest) registers the option.
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/clnrest-use-options.py')
    l2 = node_factory.get_node(options={'rest-port': rest_port,
                                        'rest-host': rest_host,
                                        'plugin': plugin,
                                        'allow-deprecated-apis': True})

    l2.daemon.logsearch_start = 0
    # We still rename this one, since it's for clnrest.
    assert l2.daemon.is_in_log(r'UNUSUAL lightningd: Option rest-host=.* deprecated in v23\.11, renaming to clnrest-host')

    # This one does not get renamed!
    assert not l2.daemon.is_in_log(r'UNUSUAL lightningd: Option rest-port=.* deprecated in v23\.11, renaming to clnrest-host')
    assert [p for p in l2.rpc.plugin('list')['plugins'] if p['name'].endswith('clnrest')] == []
    assert l2.daemon.is_in_log(r'plugin-clnrest: Killing plugin: disabled itself at init: `clnrest-port` option is not configured')
    assert l2.daemon.is_in_log(rf'clnrest-use-options.py: rest-port is {rest_port}')
