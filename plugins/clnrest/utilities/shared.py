import json5
import ipaddress
import pyln.client


CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT, REST_CSP, SWAGGER_ROOT, REST_CORS_ORIGINS = "", "", "", "", "", "", []


class RuneError(Exception):
    def __init__(self, error=str({"code": 1501, "message": "Not authorized: Missing or invalid rune"})):
        self.error = error
        super().__init__(self.error)


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
        # Ports <= 1024 are reserved for system processes
        return 1024 <= port <= 65535
    except ValueError:
        return False


def set_config(options):
    if 'clnrest-port' not in options:
        return "`clnrest-port` option is not configured"
    global CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT, REST_CSP, SWAGGER_ROOT, REST_CORS_ORIGINS

    REST_PORT = int(options["clnrest-port"])
    if validate_port(REST_PORT) is False:
        return f"`clnrest-port` {REST_PORT}, should be a valid available port between 1024 and 65535."

    REST_HOST = str(options["clnrest-host"])
    if REST_HOST != "localhost" and validate_ip4(REST_HOST) is False and validate_ip6(REST_HOST) is False:
        return f"`clnrest-host` should be a valid IP."

    REST_PROTOCOL = str(options["clnrest-protocol"])
    if REST_PROTOCOL != "http" and REST_PROTOCOL != "https":
        return f"`clnrest-protocol` can either be http or https."

    CERTS_PATH = str(options["clnrest-certs"])
    REST_CSP = str(options["clnrest-csp"])
    SWAGGER_ROOT = str(options["clnrest-swagger-root"])
    cors_origins = options["clnrest-cors-origins"]
    REST_CORS_ORIGINS.clear()
    for origin in cors_origins:
        REST_CORS_ORIGINS.append(str(origin))

    return None


def convert_millisatoshis(item):
    """
    The global JSON encoder has been replaced (see
    monkey_patch_json!)  by one that turns Millisatoshi class object
    into strings ending in msat.  We do not want the http response
    to be encoded like that!  pyln-client should probably not do that,
    but meanwhile, convert them to integers.
    """
    if isinstance(item, dict):
        ret = {}
        for k in item:
            ret[k] = convert_millisatoshis(item[k])
    elif isinstance(item, list):
        ret = [convert_millisatoshis(i) for i in item]
    elif isinstance(item, pyln.client.Millisatoshi):
        ret = int(item)
    else:
        ret = item
    return ret


def call_rpc_method(plugin, rpc_method, payload):
    return convert_millisatoshis(plugin.rpc.call(rpc_method, payload))


def verify_rune(plugin, rune, rpc_method, rpc_params):
    if rune is None:
        raise RuneError({"code": 1501, "message": "Not authorized: Missing rune"})

    return call_rpc_method(plugin, "checkrune",
                           {"rune": rune,
                            "method": rpc_method,
                            "params": rpc_params})


def process_help_response(help_response):
    # Use json5.loads due to single quotes in response
    processed_res = json5.loads(str(help_response))["help"]
    line = "\n---------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"
    processed_html_res = ""
    for row in processed_res:
        processed_html_res += f"Command: {row['command']}\n"
        processed_html_res += f"Category: {row['category']}\n"
        processed_html_res += f"Description: {row['description']}\n"
        processed_html_res += f"Verbose: {row['verbose']}\n"
        processed_html_res += line
    return processed_html_res
