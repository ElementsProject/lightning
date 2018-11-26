#!/usr/bin/env python3
"""Simple plugin to show how to build new plugins for c-lightning

It demonstrates how a plugin communicates with c-lightning, how it
registers command line arguments that should be passed through and how
it can register JSON-RPC commands. We communicate with the main daemon
through STDIN and STDOUT, reading and writing JSON-RPC requests.

"""
import json
import sys


greeting = "World"


def json_hello(request, name):
    greeting = "Hello {}".format(name)
    return greeting


def json_getmanifest(request):
    global greeting
    return {
        "options": [
            {"name": "greeting",
             "type": "string",
             "default": greeting,
             "description": "What name should I call you?"},
        ],
        "rpcmethods": [
            {
                "name": "hello",
                "description": "Returns a personalized greeting for {name}",
            },
        ]
    }


def json_init(request, options):
    """The main daemon is telling us the relevant cli options
    """
    global greeting

    greeting = request['params']['options']['greeting']
    return "ok"


methods = {
    'hello': json_hello,
    'getmanifest': json_getmanifest,
    'init': json_init,
}


partial = ""
for l in sys.stdin:
    partial += l
    try:
        request = json.loads(partial)
        result = None
        method = methods[request['method']]
        params = request['params']
        if isinstance(params, dict):
            result = method(request, **params)
        else:
            result = method(request, *params)

        result = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request['id']
        }
        json.dump(result, fp=sys.stdout)
        sys.stdout.write('\n')
        sys.stdout.flush()
        partial = ""
    except Exception:
        pass
