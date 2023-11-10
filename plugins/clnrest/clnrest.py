#!/usr/bin/env python3
# For --hidden-import gunicorn.glogging gunicorn.workers.sync
try:
    from gevent import monkey
    monkey.patch_ssl()
    import sys
    import os
    import re
    import ssl
    import time
    import multiprocessing
    from gunicorn import glogging  # noqa: F401
    from gunicorn.workers import sync  # noqa: F401

    from pathlib import Path
    from flask import Flask, request, Blueprint
    from flask_restx import Api
    from flask_cors import CORS
    from gunicorn.app.base import BaseApplication
    from multiprocessing import Process, Queue
    from flask_socketio import SocketIO, disconnect
    from utilities.generate_certs import generate_certs
    from utilities.shared import set_config, verify_rune
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


def check_origin(origin):
    from utilities.shared import REST_CORS_ORIGINS
    is_whitelisted = False
    if REST_CORS_ORIGINS[0] == "*":
        is_whitelisted = True
    else:
        for whitelisted_origin in REST_CORS_ORIGINS:
            try:
                does_match = bool(re.compile(whitelisted_origin).match(origin))
                is_whitelisted = is_whitelisted or does_match
            except Exception as err:
                plugin.log(f"Error from rest-cors-origin {whitelisted_origin} match with {origin}: {err}", "info")
    return is_whitelisted


jobs = {}
app = Flask(__name__)
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins=check_origin)
msgq = Queue()


def broadcast_from_message_queue():
    while True:
        while not msgq.empty():
            msg = msgq.get()
            if msg is None:
                return
            socketio.emit("message", msg)
        # Wait for a second after processing all items in the queue
        time.sleep(1)


# Starts a background task which pulls notifications from the message queue
# and broadcasts them to all connected ws clients at one-second intervals.
socketio.start_background_task(broadcast_from_message_queue)


@socketio.on("message")
def handle_message(message):
    plugin.log(f"Received message from client: {message}", "debug")
    socketio.emit('message', {"client_message": message, "session": request.sid})


@socketio.on("connect")
def ws_connect():
    try:
        plugin.log("Client Connecting...", "debug")
        rune = request.headers.get("rune", None)
        is_valid_rune = verify_rune(plugin, rune, "listclnrest-notifications", None)
        if "error" in is_valid_rune:
            # Logging as error/warn emits the event for all clients
            plugin.log(f"Error: {is_valid_rune}", "info")
            raise Exception(is_valid_rune)

        plugin.log("Client Connected", "debug")
        return True

    except Exception as err:
        # Logging as error/warn emits the event for all clients
        plugin.log(f"{err}", "info")
        disconnect()


def create_app():
    from utilities.shared import REST_CORS_ORIGINS
    global app
    app.config["SECRET_KEY"] = os.urandom(24).hex()
    authorizations = {
        "rune": {"type": "apiKey", "in": "header", "name": "Rune"}
    }
    CORS(app, resources={r"/*": {"origins": REST_CORS_ORIGINS}})
    blueprint = Blueprint("api", __name__)
    api = Api(blueprint, version="1.0", title="Core Lightning Rest", description="Core Lightning REST API Swagger", authorizations=authorizations, security=["rune"])
    app.register_blueprint(blueprint)
    api.add_namespace(rpcns, path="/v1")


@app.after_request
def add_csp_headers(response):
    try:
        from utilities.shared import REST_CSP
        response.headers['Content-Security-Policy'] = REST_CSP.replace('\\', '').replace("[\"", '').replace("\"]", '')
        return response
    except Exception as err:
        plugin.log(f"Error from clnrest-csp config: {err}", "info")


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
        try:
            if not cert_file.is_file() or not key_file.is_file():
                plugin.log(f"Certificate not found at {CERTS_PATH}. Generating a new certificate!", "debug")
                generate_certs(plugin, REST_HOST, CERTS_PATH)
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
            "ssl_version": ssl.PROTOCOL_TLSv1_2
        }
    return options


class CLNRestApplication(BaseApplication):
    def __init__(self, app, options=None):
        from utilities.shared import REST_PROTOCOL, REST_HOST, REST_PORT
        self.application = app
        self.options = options or {}
        super().__init__()
        plugin.log(f"REST server running at {REST_PROTOCOL}://{REST_HOST}:{REST_PORT}", "info")

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
        msgq.put(kwargs)


try:
    plugin.run()
except ValueError as err:
    plugin.log("Unable to subscribe to all events. Feature available with CLN v23.08 and above: {}".format(err), "warn")
except (KeyboardInterrupt, SystemExit):
    pass
