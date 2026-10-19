#!/usr/bin/env python3
"""Mock LSPS2 service, used to test the LSPS2 client.

Runs on the LSP node. Implements the service side of bLIP-50 (LSPS0) and
bLIP-52 (LSPS2) from the spec text, independently of any other
implementation in this repository, so that client and mock do not share
bugs. It answers `lsps0.list_protocols`, `lsps2.get_info` and
`lsps2.buy`.

What the mock does is driven by a config with one entry per phase:
`transport`, `list_protocols`, `get_info` and `buy`. Each
entry names a `behavior` plus its parameters; `honest` follows the spec.
Set the config at startup with the `lsps2-mock-config` option (JSON) or at
runtime with `lsps2-mock-configure`. Every call starts from the defaults,
so a config only lists what differs from them.

Everything the mock receives, sends and decides is recorded and returned by
`lsps2-mock-state`.
"""

import json
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from pyln.client import Plugin, RpcException

plugin = Plugin()

LSPS0_MESSAGE_TYPE = 37913

# Allocated jit_channel_scids are `SCID_BLOCK`x`n`x0, far above any block
# height a regtest test reaches, so they never collide with real channels.
SCID_BLOCK = 1_000_000

# Default parameters per phase. A phase config replaces the defaults key by
# key.
DEFAULT_CONFIG = {
    "transport": {"behavior": "honest"},
    "list_protocols": {"behavior": "honest", "protocols": [2]},
    "get_info": {
        "behavior": "honest",
        # Menu entries as sent on the wire. Missing `valid_until` and
        # `promise` are filled in when the menu is sent.
        "menu": [
            {
                "min_fee_msat": "1000",
                "proportional": 0,
                "min_lifetime": 1008,
                "max_client_to_self_delay": 2016,
                "min_payment_size_msat": "1000",
                "max_payment_size_msat": "100000000",
            }
        ],
        "valid_for_seconds": 3600,
    },
    "buy": {
        "behavior": "honest",
        "lsp_cltv_expiry_delta": 144,
        "client_trusts_lsp": False,
    },
}

# Behaviors per phase, with the parameters each one accepts on top of the
# phase defaults.
BEHAVIORS = {
    "transport": {"honest": set()},
    "list_protocols": {"honest": set()},
    "get_info": {"honest": set()},
    "buy": {"honest": set()},
}


class LspsError(Exception):
    """A JSON-RPC error to send back to the client."""

    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.error = {"code": code, "message": message}
        if data is not None:
            self.error["data"] = data


class Session:
    def __init__(self, scid, peer_id, params, payment_size_msat):
        self.scid = scid
        self.peer_id = peer_id
        self.params = params
        self.payment_size_msat = payment_size_msat

    def to_json(self):
        return {
            "jit_channel_scid": self.scid,
            "peer_id": self.peer_id,
            "opening_fee_params": self.params,
            "payment_size_msat": self.payment_size_msat,
        }


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.config = build_config({})
        # promise -> the opening_fee_params it was issued for.
        self.issued = {}
        self.sessions = {}
        self.events = []
        self.promise_counter = 0
        self.scid_counter = 0


def build_config(overrides):
    if not isinstance(overrides, dict):
        raise RpcException("config must be an object")
    config = deepcopy(DEFAULT_CONFIG)
    for phase, entry in overrides.items():
        if phase not in DEFAULT_CONFIG:
            raise RpcException(f"unknown phase {phase!r}")
        if not isinstance(entry, dict):
            raise RpcException(f"config for {phase!r} must be an object")
        behavior = entry.get("behavior", "honest")
        if behavior not in BEHAVIORS[phase]:
            raise RpcException(f"unknown behavior {behavior!r} for {phase!r}")
        allowed = set(DEFAULT_CONFIG[phase]) | BEHAVIORS[phase][behavior]
        unknown = set(entry) - allowed
        if unknown:
            raise RpcException(
                f"unknown parameters {sorted(unknown)} for {phase}.{behavior}"
            )
        config[phase].update(deepcopy(entry))
    return config


state = State()


def record(kind, **fields):
    with state.lock:
        state.events.append({"type": kind, **fields})


def lsps_datetime(dt):
    """Format a datetime as LSPS0.datetime: YYYY-MM-DDThh:mm:ss.uuuZ."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_lsps_datetime(s):
    dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.replace(tzinfo=timezone.utc)


# --- Transport (bLIP-50) ---------------------------------------------------


def send_raw(peer_id, payload):
    """Send `payload` (bytes) as an LSPS0 message to `peer_id`."""
    record("tx", peer_id=peer_id, payload=payload.decode("utf-8", "replace"))
    msg = LSPS0_MESSAGE_TYPE.to_bytes(2, "big") + payload
    plugin.rpc.sendcustommsg(peer_id, msg.hex())


def respond(peer_id, method, req_id, response):
    """Send a response through the configured transport behavior."""
    message = {"jsonrpc": "2.0", **response, "id": req_id}
    send_raw(peer_id, json.dumps(message).encode())


def handle_message(peer_id, raw):
    try:
        req = json.loads(raw.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError("not an object")
    except ValueError:
        respond(
            peer_id, None, None, {"error": {"code": -32700, "message": "Parse error"}}
        )
        return

    req_id = req.get("id")
    method = req.get("method")
    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        respond(
            peer_id,
            method,
            req_id,
            {"error": {"code": -32600, "message": "Invalid Request"}},
        )
        return

    handler = METHODS.get(method)
    if handler is None:
        respond(
            peer_id,
            method,
            req_id,
            {"error": {"code": -32601, "message": "Method not found"}},
        )
        return

    params = req.get("params", {})
    try:
        if not isinstance(params, dict):
            raise LspsError(-32602, "Invalid params", {"unrecognized": []})
        response = {"result": handler(peer_id, params)}
    except LspsError as e:
        response = {"error": e.error}
    respond(peer_id, method, req_id, response)


def check_params(params, known):
    unknown = sorted(set(params) - set(known))
    if unknown:
        raise LspsError(-32602, "Invalid params", {"unrecognized": unknown})


# --- lsps0.list_protocols --------------------------------------------------


def list_protocols(peer_id, params):
    check_params(params, [])
    return {"protocols": state.config["list_protocols"]["protocols"]}


# --- lsps2.get_info --------------------------------------------------------


def get_info(peer_id, params):
    check_params(params, ["token"])
    cfg = state.config["get_info"]
    valid_until = lsps_datetime(
        datetime.now(timezone.utc) + timedelta(seconds=cfg["valid_for_seconds"])
    )
    menu = []
    with state.lock:
        for entry in cfg["menu"]:
            entry = deepcopy(entry)
            entry.setdefault("valid_until", valid_until)
            if "promise" not in entry:
                state.promise_counter += 1
                entry["promise"] = f"mock-promise-{state.promise_counter:04d}"
            state.issued[entry["promise"]] = deepcopy(entry)
            menu.append(entry)
    return {"opening_fee_params_menu": menu}


# --- lsps2.buy -------------------------------------------------------------


def buy(peer_id, params):
    check_params(params, ["opening_fee_params", "payment_size_msat"])
    cfg = state.config["buy"]

    # The promise is a lookup key into what we issued: the params are valid
    # only if they equal, field by field, an entry we sent.
    ofp = params.get("opening_fee_params")
    promise = ofp.get("promise") if isinstance(ofp, dict) else None
    with state.lock:
        issued = state.issued.get(promise) if isinstance(promise, str) else None
    if issued is None or issued != ofp:
        raise LspsError(201, "invalid_opening_fee_params")
    if parse_lsps_datetime(ofp["valid_until"]) <= datetime.now(timezone.utc):
        raise LspsError(201, "invalid_opening_fee_params")

    payment_size_msat = None
    if "payment_size_msat" in params:
        try:
            payment_size_msat = int(params["payment_size_msat"])
        except (TypeError, ValueError):
            raise LspsError(-32602, "Invalid params", {"unrecognized": []})
        if payment_size_msat < int(ofp["min_payment_size_msat"]):
            raise LspsError(202, "payment_size_too_small")
        if payment_size_msat > int(ofp["max_payment_size_msat"]):
            raise LspsError(203, "payment_size_too_large")

    with state.lock:
        state.scid_counter += 1
        scid = f"{SCID_BLOCK}x{state.scid_counter}x0"
        session = Session(scid, peer_id, ofp, payment_size_msat)
        state.sessions[scid] = session
    record("buy", **session.to_json())

    return {
        "jit_channel_scid": scid,
        "lsp_cltv_expiry_delta": cfg["lsp_cltv_expiry_delta"],
        "client_trusts_lsp": cfg["client_trusts_lsp"],
    }


METHODS = {
    "lsps0.list_protocols": list_protocols,
    "lsps2.get_info": get_info,
    "lsps2.buy": buy,
}


@plugin.hook("custommsg", filters=[LSPS0_MESSAGE_TYPE])
def on_custommsg(peer_id, payload, **kwargs):
    raw = bytes.fromhex(payload)
    if int.from_bytes(raw[:2], "big") == LSPS0_MESSAGE_TYPE:
        raw = raw[2:]
        record("rx", peer_id=peer_id, payload=raw.decode("utf-8", "replace"))
        handle_message(peer_id, raw)
    return {"result": "continue"}


# --- Test control ----------------------------------------------------------


@plugin.method("lsps2-mock-configure")
def lsps2_mock_configure(config, **kwargs):
    """Replace the mock's config; phases left out use the defaults."""
    new_config = build_config(config)
    with state.lock:
        state.config = new_config
    return {"config": new_config}


@plugin.method("lsps2-mock-state")
def lsps2_mock_state(**kwargs):
    """Return config, sessions and every recorded event."""
    with state.lock:
        return {
            "config": state.config,
            "sessions": [s.to_json() for s in state.sessions.values()],
            "events": state.events,
        }


plugin.add_option(
    "lsps2-mock-config",
    "{}",
    "Initial mock config as JSON, see lsps2-mock-configure.",
)


@plugin.init()
def init(options, **kwargs):
    state.config = build_config(json.loads(options["lsps2-mock-config"]))


plugin.run()
