#!/usr/bin/env python
"""Simple plugin to show how to build new plugins for c-lightning

It demonstrates how a plugin communicates with c-lightning, how it registers
command line arguments that should be passed through and how it can register
JSON-RPC commands. We communicate with the main daemon through STDIN and STDOUT,
reading and writing JSON-RPC requests.

"""
import json
import sys


greeting = "World"


def json_hello(request):
    greeting = "Hello {}".format(request['params']['name'])
    return greeting


def json_init(request):
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


def json_configure(request):
    """The main daemon is telling us the relevant cli options
    """
    global greeting

    greeting = request['params']['options']['greeting']
    return "ok"


def json_ping(request):
    return "pong"


methods = {
    'hello': json_hello,
    'init': json_init,
    'ping': json_ping,
    'configure': json_configure,
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
