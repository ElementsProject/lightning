#!/usr/bin/env python3
try:
    import websockets
    import asyncio
    import os
    import datetime
    import ipaddress
    import multiprocessing
    import ssl
    from pathlib import Path
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from pyln.client import Plugin
except ModuleNotFoundError as err:
    # OK, something is not installed?
    import json
    import sys
    getmanifest = json.loads(sys.stdin.readline())
    print(json.dumps({'jsonrpc': "2.0",
                      'id': getmanifest['id'],
                      'result': {'disable': str(err)}}))
    sys.exit(1)

plugin = Plugin(autopatch=False)

WSS_BIND_HOST, WSS_BIND_PORT, WSS_WS_HOST, WSS_WS_PORT, WSS_CERTS = "", None, "", None, ""

plugin.add_option(name="wss-bind-addr", default=None, description="WSS proxy address to connect with WS", opt_type="string", deprecated=False)
plugin.add_option(name="wss-certs", default=os.getcwd(), description="Certificate location for WSS proxy", opt_type="string", deprecated=False)


def validate_ip4(ip_str):
    try:
        # Create an IPv4 address object.
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_ip6(ip_str):
    try:
        # Create an IPv6 address object.
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_port(port):
    try:
        # Ports <= 1024 are reserved for system processes.
        return 1024 <= port <= 65535
    except ValueError:
        return False


def set_config(options):
    if 'wss-bind-addr' not in options:
        return "`wss-bind-addr` option is not configured"
    global WSS_BIND_HOST, WSS_BIND_PORT, WSS_WS_HOST, WSS_WS_PORT, WSS_CERTS
    try:
        WSS_BIND_HOST, WSS_BIND_PORT = str(options["wss-bind-addr"]).rsplit(":", 1)
        WSS_BIND_PORT = int(WSS_BIND_PORT) if WSS_BIND_PORT else None
        if WSS_BIND_HOST != "localhost" and validate_ip4(WSS_BIND_HOST) is False and validate_ip6(WSS_BIND_HOST) is False:
            return f"WSS host should be a valid IP. Current Value: {WSS_BIND_HOST}."
        if validate_port(WSS_BIND_PORT) is False:
            return f"WSS post {WSS_BIND_PORT}, should be a valid available port between 1024 and 65535. Current Value: {WSS_BIND_PORT}."
        # Extract from the list of configs['bind addr'] not bind-addr directly
        # to avoid error when value is passed by cmdline.
        listconfigs = plugin.rpc.listconfigs()
        wsaddress = next((addr for addr in listconfigs['configs']['bind-addr']['values_str'] if addr.startswith('ws:')), None)
        WSS_WS_HOST, WSS_WS_PORT = (wsaddress[3:]).rsplit(":", 1)
        WSS_WS_PORT = int(WSS_WS_PORT) if WSS_WS_PORT else None
        if WSS_WS_HOST != "localhost" and validate_ip4(WSS_WS_HOST) is False and validate_ip6(WSS_WS_HOST) is False:
            return f"`bind-addr` with `ws:` IP should be a valid IP. Current Value: {WSS_WS_HOST}."
        if validate_port(WSS_WS_PORT) is False:
            return f"`bind-addr` with `ws` port should be a valid available port between 1024 and 65535. Current Value: {WSS_WS_PORT}."
        WSS_CERTS = str(options["wss-certs"])
    except Exception as err:
        return f"Error in parsing options: {err}"
    return None


def save_cert(entity_type, cert, private_key, certs_path):
    """Serialize and save certificates and keys.
    `entity_type` is either "ca", "client" or "server"."""
    with open(os.path.join(certs_path, f"{entity_type}.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(certs_path, f"{entity_type}-key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))


def create_cert_builder(subject_name, issuer_name, public_key, wss_host):
    list_sans = [x509.DNSName("cln"), x509.DNSName("localhost")]
    if validate_ip4(wss_host) is True:
        list_sans.append(x509.IPAddress(ipaddress.IPv4Address(wss_host)))

    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10 * 365))  # Ten years validity
        .add_extension(x509.SubjectAlternativeName(list_sans), critical=False)
    )


def generate_cert(entity_type, ca_subject, ca_private_key, wss_host, certs_path):
    # Generate Key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Generate Certificates
    if isinstance(ca_subject, x509.Name):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"cln wss proxy {entity_type}")])
        cert_builder = create_cert_builder(subject, ca_subject, public_key, wss_host)
        cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    else:
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"cln wss proxy CA")])
        ca_private_key, ca_public_key = private_key, public_key
        cert_builder = create_cert_builder(ca_subject, ca_subject, ca_public_key, wss_host)
        cert = (
            cert_builder
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_private_key, hashes.SHA256())
        )

    os.makedirs(certs_path, exist_ok=True)
    save_cert(entity_type, cert, private_key, certs_path)
    return ca_subject, ca_private_key


def generate_certs(plugin, wss_host, certs_path):
    ca_subject, ca_private_key = generate_cert("ca", None, None, wss_host, certs_path)
    generate_cert("client", ca_subject, ca_private_key, wss_host, certs_path)
    generate_cert("server", ca_subject, ca_private_key, wss_host, certs_path)
    plugin.log(f"Certificates Generated!", "debug")


async def relay_messages(wss_server):
    try:
        ws_server = await websockets.connect(f"ws://{WSS_WS_HOST}:{WSS_WS_PORT}")

        async def wss_to_ws():
            while True:
                message = await wss_server.recv()
                await ws_server.send(message)

        async def ws_to_wss():
            while True:
                message = await ws_server.recv()
                await wss_server.send(message)

        await asyncio.gather(wss_to_ws(), ws_to_wss())
    except Exception as err:
        plugin.log(f"Message Relay Error: {err}", "debug")
    finally:
        await wss_server.close()
        await ws_server.close()
        plugin.log(f"Connection Closed!", "debug")


async def start_server():
    cert_file = Path(f"{WSS_CERTS}/client.pem")
    key_file = Path(f"{WSS_CERTS}/client-key.pem")
    try:
        if not cert_file.is_file() or not key_file.is_file():
            plugin.log(f"Certificate not found at {WSS_CERTS}. Generating a new certificate!", "debug")
            generate_certs(plugin, WSS_BIND_HOST, WSS_CERTS)
    except Exception as err:
        raise Exception(f"{err}: Certificates do not exist at {WSS_CERTS}")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(f"{WSS_CERTS}/client.pem", f"{WSS_CERTS}/client-key.pem")
    async with websockets.serve(relay_messages, WSS_BIND_HOST, WSS_BIND_PORT, ssl=ssl_context):
        await asyncio.Future()


def run_server():
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        asyncio.get_event_loop().run_until_complete(start_server())
    except OSError as os_err:
        plugin.log(f"Killing plugin: disabled itself after OSError {os_err}", "warn")
        return {'disable': os_err}
    except Exception as err:
        plugin.log(f"Killing plugin: disabled itself after Error {err}", "warn")
        return {'disable': err}


@plugin.init()
def init(options, configuration, plugin):
    plugin.log(f"Initiating websocket secure server...", "debug")
    err = set_config(options)
    if err:
        return {'disable': err}
    plugin.log(f"WSS Options: {WSS_BIND_HOST}, {WSS_BIND_PORT}, {WSS_WS_HOST}, {WSS_WS_PORT}, {WSS_CERTS}", "debug")
    try:
        server_process = multiprocessing.Process(target=run_server, daemon=True, name="Websocket Secure Server")
        server_process.start()
        plugin.log(f"Websocket Secure Server Started", "debug")
        return True
    except OSError as os_err:
        return {'disable': os_err}
    except Exception as err:
        return {'disable': err}


try:
    plugin.run()
except Exception as err:
    plugin.log("Error: {}".format(err), "warn")
except (KeyboardInterrupt, SystemExit):
    pass
