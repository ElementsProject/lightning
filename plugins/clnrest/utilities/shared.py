import json5
import re
import json

CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT, REST_CSP, REST_CORS_ORIGINS = "", "", "", "", "", []


def set_config(options):
    if 'rest-port' not in options:
        return "`rest-port` option is not configured"
    global CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT, REST_CSP, REST_CORS_ORIGINS
    CERTS_PATH = str(options["rest-certs"])
    REST_PROTOCOL = str(options["rest-protocol"])
    REST_HOST = str(options["rest-host"])
    REST_PORT = int(options["rest-port"])
    REST_CSP = str(options["rest-csp"])
    cors_origins = options["rest-cors-origins"]
    REST_CORS_ORIGINS.clear()
    for origin in cors_origins:
        REST_CORS_ORIGINS.append(str(origin))

    return None


def call_rpc_method(plugin, rpc_method, payload):
    try:
        response = plugin.rpc.call(rpc_method, payload)
        if '"error":' in str(response).lower():
            raise Exception(response)
        else:
            plugin.log(f"{response}", "debug")
            if '"result":' in str(response).lower():
                # Use json5.loads ONLY when necessary, as it increases processing time significantly
                return json.loads(response)["result"]
            else:
                return response

    except Exception as err:
        plugin.log(f"Error: {err}", "error")
        if "error" in str(err).lower():
            match_err_obj = re.search(r'"error":\{.*?\}', str(err))
            if match_err_obj is not None:
                err = "{" + match_err_obj.group() + "}"
            else:
                match_err_str = re.search(r"error: \{.*?\}", str(err))
                if match_err_str is not None:
                    err = "{" + match_err_str.group() + "}"
        raise Exception(err)


def verify_rune(plugin, request):
    rune = request.headers.get("rune", None)

    if rune is None:
        raise Exception('{ "error": {"code": 403, "message": "Not authorized: Missing rune"} }')

    if request.is_json:
        if len(request.data) != 0:
            rpc_params = request.get_json()
        else:
            rpc_params = {}
    else:
        rpc_params = request.form.to_dict()

    # None, if this isn't present.
    rpc_method = request.view_args.get("rpc_method")

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
