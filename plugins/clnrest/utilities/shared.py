import json5
import re
import json

CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT = "", "", "", ""

def set_config(options):
    global CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT
    CERTS_PATH = str(options["rest-certs"])
    REST_PROTOCOL = str(options["rest-protocol"])
    REST_HOST = str(options["rest-host"])
    REST_PORT = int(options["rest-port"])

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
    nodeid = request.headers.get("nodeid", None)

    if nodeid is None:
        raise Exception('{ "error": {"code": 403, "message": "Not authorized: Missing nodeid"} }')

    if rune is None:
        raise Exception('{ "error": {"code": 403, "message": "Not authorized: Missing rune"} }')

    if request.is_json:
        rpc_params = request.get_json()
    else:
        rpc_params = request.form.to_dict()

    return call_rpc_method(plugin, "commando-checkrune", [nodeid, rune, request.view_args["rpc_method"], rpc_params])

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
