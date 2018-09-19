#!/usr/bin/env python
"""Simple plugin to show how to build new plugins for c-lightning

It demonstrates how a plugin communicates with c-lightning, how it registers
command line arguments that should be passed through and how it can register
JSON-RPC commands. We communicate with the main daemon through STDIN and STDOUT,
reading and writing JSON-RPC requests.

"""
import json
import sys


def json_hello(request):
    greeting = "Hello {}".format(request['params']['name'])
    return greeting


def json_init(request):
    return {
        "options": [
            {"name": "greeting", "type": "string", "default": "World"},
        ],
        "rpcmethods": [
            {
                "name": "hello",
                "description": "Returns a personalized greeting for {name}",
            },
        ]
    }


def json_configure(request):
    """The main daemon is telling us the relevant cli options
    """
    return None


def json_ping(request):
    return "pong"


methods = {
    'hello': json_hello,
    'init': json_init,
    'ping': json_ping,
}


partial = ""
for l in sys.stdin:
    partial += l
    try:
        request = json.loads(partial)
        result = {
            "jsonrpc": "2.0",
            "result": methods[request['method']](request),
            "id": request['id']
        }
        json.dump(result, fp=sys.stdout)
        sys.stdout.write('\n')
        sys.stdout.flush()
        partial = ""
    except Exception:
        pass
