#!/usr/bin/env python3
"""An example plugin that fails to answer to `getmanifest`

Used to test the `getmanifest` timeout.
"""
import json
import sys
import time


def json_getmanifest(request, **kwargs):
    # Timeout is 120 seconds, so wait more
    time.sleep(121)
    return {
        "options": [
        ],
        "rpcmethods": [
        ]
    }


methods = {
    'getmanifest': json_getmanifest,
}


partial = ""
for l in sys.stdin:
    try:
        partial += l
        request = json.loads(partial)
    except Exception:
        continue

    result = None
    method = methods[request['method']]
    params = request['params']
    try:
        if isinstance(params, dict):
            result = method(request, **params)
        else:
            result = method(request, *params)
        result = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request['id']
        }
    except Exception:
        result = {
            "jsonrpc": "2.0",
            "error": "Error while processing {}".format(request['method']),
            "id": request['id']
        }

    json.dump(result, fp=sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()
    partial = ""
