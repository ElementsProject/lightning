#!/usr/bin/env python3
# For --hidden-import gunicorn.glogging gunicorn.workers.sync
try:
    from gunicorn import glogging  # noqa: F401
    from gunicorn.workers import sync  # noqa: F401

    from pathlib import Path
    from flask import Flask
    from flask_restx import Api
    from gunicorn.app.base import BaseApplication
    from multiprocessing import Process, cpu_count
    from utilities.generate_certs import generate_certs
    from utilities.shared import set_config
    from utilities.rpc_routes import rpcns
    from utilities.rpc_plugin import plugin
except ModuleNotFoundError as err:
    # OK, something is not installed?
    import json
    import sys
    getmanfest = json.loads(sys.stdin.readline())
    print(json.dumps({'jsonrpc': "2.0",
                      'id': getmanfest['id'],
                      'result': {'disable': str(err)}}))
    sys.exit(1)

jobs = {}


def create_app():
    app = Flask(__name__)
    authorizations = {
        "rune": {"type": "apiKey", "in": "header", "name": "Rune"},
        "nodeid": {"type": "apiKey", "in": "header", "name": "Nodeid"}
    }
    api = Api(app, version="1.0", title="Core Lightning Rest", description="Core Lightning REST API Swagger", authorizations=authorizations, security=["rune", "nodeid"])
    api.add_namespace(rpcns, path="/v1")
    return app


def set_application_options(plugin):
    from utilities.shared import CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT
    plugin.log(f"REST Server is starting at {REST_PROTOCOL}://{REST_HOST}:{REST_PORT}", "debug")
    if REST_PROTOCOL == "http":
        options = {
            "bind": f"{REST_HOST}:{REST_PORT}",
            "workers": cpu_count(),
            "timeout": 60,
            "loglevel": "warning",
        }
    else:
        cert_file = Path(f"{CERTS_PATH}/client.pem")
        key_file = Path(f"{CERTS_PATH}/client-key.pem")
        if not cert_file.is_file() or not key_file.is_file():
            plugin.log(f"Certificate not found at {CERTS_PATH}. Generating a new certificate!", "debug")
            generate_certs(plugin, CERTS_PATH)
        try:
            plugin.log(f"Certs Path: {CERTS_PATH}", "debug")
        except Exception as err:
            raise Exception(f"{err}: Certificates do not exist at {CERTS_PATH}")
        options = {
            "bind": f"{REST_HOST}:{REST_PORT}",
            "workers": cpu_count(),
            "timeout": 60,
            "loglevel": "warning",
            "certfile": f"{CERTS_PATH}/client.pem",
            "keyfile": f"{CERTS_PATH}/client-key.pem",
        }
    return options


class CLNRestApplication(BaseApplication):
    def __init__(self, app, options=None):
        from utilities.shared import REST_PROTOCOL, REST_HOST, REST_PORT
        self.application = app
        self.options = options or {}
        plugin.log(f"REST server running at {REST_PROTOCOL}://{REST_HOST}:{REST_PORT}", "info")
        super().__init__()

    def load_config(self):
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def worker():
    options = set_application_options(plugin)
    app = create_app()
    CLNRestApplication(app, options).run()


def start_server():
    from utilities.shared import REST_PORT
    if REST_PORT in jobs:
        return False, "server already running"

    p = Process(
        target=worker,
        args=[],
        name="server on port {}".format(REST_PORT),
    )
    p.daemon = True
    jobs[REST_PORT] = p
    p.start()
    return True


@plugin.init()
def init(options, configuration, plugin):
    # We require options before we open a port.
    err = set_config(options)
    if err:
        return {'disable': err}
    start_server()


plugin.run()
