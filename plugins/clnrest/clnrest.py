#!/usr/bin/env python3
# For --hidden-import gunicorn.glogging gunicorn.workers.sync
try:
    import sys
    import os
    import time
    import multiprocessing
    from gunicorn import glogging  # noqa: F401
    from gunicorn.workers import sync  # noqa: F401

    from pathlib import Path
    from flask import Flask
    from flask_restx import Api
    from gunicorn.app.base import BaseApplication
    from multiprocessing import Process, Queue
    from flask_socketio import SocketIO
    from utilities.generate_certs import generate_certs
    from utilities.shared import set_config
    from utilities.rpc_routes import rpcns
    from utilities.rpc_plugin import plugin
except ModuleNotFoundError as err:
    # OK, something is not installed?
    import json
    getmanifest = json.loads(sys.stdin.readline())
    print(json.dumps({'jsonrpc': "2.0",
                      'id': getmanifest['id'],
                      'result': {'disable': str(err)}}))
    sys.exit(1)

multiprocessing.set_start_method('fork')

jobs = {}
app = Flask(__name__)
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*")
msgq = Queue()


def broadcast_from_message_queue():
    while True:
        while not msgq.empty():
            msg = msgq.get()
            if msg is None:
                return
            plugin.log(f"Emitting message: {msg}", "debug")
            socketio.emit("message", msg)
        # Wait for a second after processing all items in the queue
        time.sleep(1)


# Starts a background task which pulls notifications from the message queue
# and broadcasts them to all connected ws clients at one-second intervals.
socketio.start_background_task(broadcast_from_message_queue)


@socketio.on("connect", namespace="/ws")
def ws_connect():
    plugin.log("Client Connected", "debug")
    msgq.put("Client Connected")


@socketio.on("disconnect", namespace="/ws")
def ws_disconnect():
    plugin.log("Client Disconnected", "debug")
    msgq.put("Client Disconnected")


def create_app():
    global app
    app.config['SECRET_KEY'] = os.urandom(24).hex()
    authorizations = {
        "rune": {"type": "apiKey", "in": "header", "name": "Rune"}
    }
    api = Api(app, version="1.0", title="Core Lightning Rest", description="Core Lightning REST API Swagger", authorizations=authorizations, security=["rune"])
    api.add_namespace(rpcns, path="/v1")


def set_application_options(plugin):
    from utilities.shared import CERTS_PATH, REST_PROTOCOL, REST_HOST, REST_PORT
    plugin.log(f"REST Server is starting at {REST_PROTOCOL}://{REST_HOST}:{REST_PORT}", "debug")
    if REST_PROTOCOL == "http":
        # Assigning only one worker due to added complexity between gunicorn's multiple worker process forks
        # and websocket connection's persistance with a single worker.
        options = {
            "bind": f"{REST_HOST}:{REST_PORT}",
            "workers": 1,
            "worker_class": "geventwebsocket.gunicorn.workers.GeventWebSocketWorker",
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
        # Assigning only one worker due to added complexity between gunicorn's multiple worker process forks
        # and websocket connection's persistance with a single worker.
        options = {
            "bind": f"{REST_HOST}:{REST_PORT}",
            "workers": 1,
            "worker_class": "geventwebsocket.gunicorn.workers.GeventWebSocketWorker",
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
    global app
    options = set_application_options(plugin)
    create_app()
    CLNRestApplication(app, options).run()


def start_server():
    global jobs
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


@plugin.subscribe("*")
def on_any_notification(request, **kwargs):
    plugin.log("Notification: {}".format(kwargs), "debug")
    if request.method == 'shutdown':
        # A plugin which subscribes to shutdown is expected to exit itself.
        sys.exit(0)
    else:
        msgq.put(str(kwargs))


try:
    plugin.run()
except ValueError as err:
    plugin.log("Unable to subscribe to all events. Feature available with CLN v23.08 and above: {}".format(err), "warn")
except (KeyboardInterrupt, SystemExit):
    pass
