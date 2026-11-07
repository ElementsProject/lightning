#!/usr/bin/env python3
"""Mock LSPS2 service, used to test the LSPS2 client.

Runs on the LSP node. Implements the service side of bLIP-50 (LSPS0) and
bLIP-52 (LSPS2) from the spec text, independently of any other
implementation in this repository, so that client and mock do not share
bugs:

- answers `lsps0.list_protocols`, `lsps2.get_info` and `lsps2.buy`,
- intercepts the HTLCs sent to a `jit_channel_scid`, opens a zero-conf
  channel to the client and forwards the parts with the opening fee
  deducted. The fee comes from lsps2_mock_fee.py.

What the mock does is driven by a config with one entry per phase:
`transport`, `list_protocols`, `get_info`, `buy`, `open` and `htlc`. Each
entry names a `behavior` plus its parameters; `honest` follows the spec.
Set the config at startup with the `lsps2-mock-config` option (JSON) or at
runtime with `lsps2-mock-configure`. Every call starts from the defaults,
so a config only lists what differs from them.

Everything the mock receives, sends and decides is recorded and returned by
`lsps2-mock-state`.
"""

import functools
import json
import threading
import traceback
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from lsps2_mock_fee import FeeOverflow, opening_fee
from pyln.client import Plugin, RpcError, RpcException
from pyln.client.plugin import RequestState

plugin = Plugin()

LSPS0_MESSAGE_TYPE = 37913
TLV_AMT_TO_FORWARD = 2
TLV_EXTRA_FEE = 65537
# Failure messages from BOLT 4.
UNKNOWN_NEXT_PEER = "400a"
TEMPORARY_NODE_FAILURE = "2002"
# With an empty channel_update.
TEMPORARY_CHANNEL_FAILURE = "10070000"

# Allocated jit_channel_scids are `SCID_BLOCK`x`n`x0, far above any block
# height a regtest test reaches, so they never collide with real channels.
SCID_BLOCK = 1_000_000

# Default parameters per phase. A phase config replaces the defaults key by
# key.
DEFAULT_CONFIG = {
    # `methods` limits a transport misbehavior to responses to these methods;
    # None means all.
    "transport": {"behavior": "honest", "methods": None},
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
        # None allocates a fresh SCID per session.
        "jit_channel_scid": None,
        "lsp_cltv_expiry_delta": 144,
        "client_trusts_lsp": False,
    },
    "open": {"behavior": "honest", "capacity_sat": 100_000},
    # `fee_msat` is the fee to deduct; None deducts the opening fee computed
    # from the session's params. `clock_offset_seconds` moves the clock the
    # mock checks valid_until against, so a test can let a session expire
    # without waiting.
    "htlc": {"behavior": "honest", "fee_msat": None, "clock_offset_seconds": 0},
}

REQUIRED = object()

# Parameters whose value must be a list, or None where that is the default.
LIST_PARAMS = {"methods", "protocols", "menu", "deductions", "extra_fees", "parts"}

# Behaviors per phase, with the parameters each one takes on top of the
# phase defaults, and their defaults. A new attack is a new entry here plus
# its handling in the phase.
BEHAVIORS = {
    "transport": {
        "honest": {},
        # Send nothing.
        "drop": {},
        # Answer with a different JSON-RPC id.
        "wrong_id": {"id": "mock-wrong-id"},
        # Send the response twice; `change` is merged into the second
        # result.
        "duplicate": {"change": {}},
        # Send `payload` verbatim instead of the response.
        "replace": {"payload": REQUIRED},
        # Merge `fields` into the result.
        "add_fields": {"fields": REQUIRED},
        # Answer with `error` instead of the result.
        "error": {"error": REQUIRED},
    },
    "list_protocols": {"honest": {}},
    "get_info": {"honest": {}},
    "buy": {"honest": {}},
    "open": {
        "honest": {},
        # Never open; fail the collected parts.
        "never": {},
        # Open a second zero-conf channel after the first.
        "twice": {},
    },
    "htlc": {
        "honest": {},
        # Deduct `deductions[i]` from part i (in arrival order, 0 beyond the
        # list) and send `extra_fees[i]` as extra_fee, None omits the TLV.
        # Without `extra_fees` the extra_fee matches the deduction.
        "deduct": {"deductions": REQUIRED, "extra_fees": None},
        # Forward only the parts with these indices, fail the others.
        "forward_subset": {"parts": REQUIRED},
        # Deduct the fee again from payments after the session.
        "deduct_again": {},
    },
}


class LspsError(Exception):
    """A JSON-RPC error to send back to the client."""

    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.error = {"code": code, "message": message}
        if data is not None:
            self.error["data"] = data


class Session:
    def __init__(self, scid, peer_id, params, payment_size_msat, opening_fee_msat):
        self.scid = scid
        self.peer_id = peer_id
        self.params = params
        self.payment_size_msat = payment_size_msat
        # Known at buy in MPP+fixed-invoice mode, set by the first HTLC in
        # no-MPP+var-invoice mode.
        self.opening_fee_msat = opening_fee_msat
        # collecting -> opening -> forwarded
        self.state = "collecting"
        self.parts = []
        # The payment that opens the channel and pays the opening fee.
        self.payment_hash = None
        self.channel_id = None
        self.htlc_minimum_msat = 0

    def to_json(self):
        return {
            "jit_channel_scid": self.scid,
            "peer_id": self.peer_id,
            "opening_fee_params": self.params,
            "payment_size_msat": self.payment_size_msat,
            "opening_fee_msat": self.opening_fee_msat,
            "state": self.state,
            "payment_hash": self.payment_hash,
            "channel_id": self.channel_id,
            "held_parts": len(self.parts),
        }


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.config = build_config({})
        # promise -> the opening_fee_params it was issued for.
        self.issued = {}
        self.sessions = {}
        self.normal_channels = set()
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
        params = BEHAVIORS[phase][behavior]
        unknown = set(entry) - set(DEFAULT_CONFIG[phase]) - set(params)
        if unknown:
            raise RpcException(
                f"unknown parameters {sorted(unknown)} for {phase}.{behavior}"
            )
        missing = [k for k, v in params.items() if v is REQUIRED and k not in entry]
        if missing:
            raise RpcException(
                f"missing parameters {missing} for {phase}.{behavior}"
            )
        defaults = {**DEFAULT_CONFIG[phase], **params}
        for key in LIST_PARAMS & set(entry):
            value = entry[key]
            if not isinstance(value, list) and not (
                value is None and defaults[key] is None
            ):
                raise RpcException(f"{phase}.{key} must be a list")
        config[phase].update(deepcopy(params))
        config[phase].update(deepcopy(entry))
    return config


state = State()


def record(kind, **fields):
    now = lsps_datetime(datetime.now(timezone.utc))
    with state.lock:
        state.events.append({"type": kind, "time": now, **fields})


def report_error(where, e, **fields):
    """Record and log the exception `e` being handled. It is a bug in the
    mock or in the test's config: it is logged as BROKEN, so the test fails
    at teardown."""
    tb = traceback.format_exc()
    record("error", where=where, error=tb, **fields)
    plugin.log(f"{where} failed: {e!r}", level="broken")
    plugin.log(tb, level="debug")


def lsps_datetime(dt):
    """Format a datetime as LSPS0.datetime: YYYY-MM-DDThh:mm:ss.uuuZ."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_lsps_datetime(s):
    dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.replace(tzinfo=timezone.utc)


# --- TLV helpers (BOLT 1 BigSize, BOLT 4 tu64) -----------------------------


def bigsize_encode(n):
    if n < 0xFD:
        return n.to_bytes(1, "big")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "big")
    return b"\xff" + n.to_bytes(8, "big")


def bigsize_decode(b, pos):
    first = b[pos]
    if first < 0xFD:
        return first, pos + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    return int.from_bytes(b[pos + 1:pos + 1 + width], "big"), pos + 1 + width


def tlv_decode(b):
    """Decode a TLV stream into a list of (type, value) pairs."""
    fields = []
    pos = 0
    while pos < len(b):
        typ, pos = bigsize_decode(b, pos)
        length, pos = bigsize_decode(b, pos)
        fields.append((typ, b[pos:pos + length]))
        pos += length
    return fields


def tlv_encode(fields):
    return b"".join(bigsize_encode(t) + bigsize_encode(len(v)) + v for t, v in fields)


def tu64(n):
    return n.to_bytes(8, "big").lstrip(b"\x00")


def payload_with_amount(payload_hex, amount_msat):
    """Return our hop payload with `amt_to_forward` replaced, without the
    length prefix (lightningd adds it back)."""
    raw = bytes.fromhex(payload_hex)
    length, pos = bigsize_decode(raw, 0)
    fields = [
        (t, tu64(amount_msat) if t == TLV_AMT_TO_FORWARD else v)
        for t, v in tlv_decode(raw[pos:pos + length])
    ]
    return tlv_encode(fields).hex()


def extra_fee_tlvs(extra_fee_msat):
    return tlv_encode([(TLV_EXTRA_FEE, extra_fee_msat.to_bytes(8, "big"))]).hex()


# --- Transport (bLIP-50) ---------------------------------------------------


def send_raw(peer_id, payload):
    """Send `payload` (bytes) as an LSPS0 message to `peer_id`."""
    record("tx", peer_id=peer_id, payload=payload.decode("utf-8", "replace"))
    msg = LSPS0_MESSAGE_TYPE.to_bytes(2, "big") + payload
    plugin.rpc.sendcustommsg(peer_id, msg.hex())


def send_json(peer_id, message):
    send_raw(peer_id, json.dumps(message).encode())


def respond(peer_id, method, req_id, response):
    """Send a response through the configured transport behavior."""
    cfg = state.config["transport"]
    message = {"jsonrpc": "2.0", **response, "id": req_id}
    behavior = cfg["behavior"]
    if cfg["methods"] is not None and method not in cfg["methods"]:
        behavior = "honest"

    if behavior == "honest":
        send_json(peer_id, message)
    elif behavior == "drop":
        record("drop", peer_id=peer_id, method=method)
    elif behavior == "wrong_id":
        send_json(peer_id, {**message, "id": cfg["id"]})
    elif behavior == "duplicate":
        send_json(peer_id, message)
        second = deepcopy(message)
        if isinstance(second.get("result"), dict):
            second["result"].update(cfg["change"])
        send_json(peer_id, second)
    elif behavior == "replace":
        send_raw(peer_id, cfg["payload"].encode())
    elif behavior == "add_fields":
        if isinstance(message.get("result"), dict):
            message["result"].update(cfg["fields"])
        send_json(peer_id, message)
    elif behavior == "error":
        message.pop("result", None)
        send_json(peer_id, {**message, "error": cfg["error"]})


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
    except Exception as e:
        report_error(method, e)
        response = {"error": {"code": -32603, "message": "Internal error"}}
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
    fee_msat = None
    if "payment_size_msat" in params:
        try:
            payment_size_msat = int(params["payment_size_msat"])
        except (TypeError, ValueError):
            raise LspsError(-32602, "Invalid params", {"unrecognized": []})
        if payment_size_msat < int(ofp["min_payment_size_msat"]):
            raise LspsError(202, "payment_size_too_small")
        if payment_size_msat > int(ofp["max_payment_size_msat"]):
            raise LspsError(203, "payment_size_too_large")
        try:
            fee_msat = params_fee(ofp, payment_size_msat)
        except FeeOverflow:
            raise LspsError(203, "payment_size_too_large")
        if fee_msat >= payment_size_msat:
            raise LspsError(202, "payment_size_too_small")

    with state.lock:
        state.scid_counter += 1
        scid = cfg["jit_channel_scid"] or f"{SCID_BLOCK}x{state.scid_counter}x0"
        session = Session(scid, peer_id, ofp, payment_size_msat, fee_msat)
        state.sessions[scid] = session
    record("buy", **session.to_json())

    return {
        "jit_channel_scid": scid,
        "lsp_cltv_expiry_delta": cfg["lsp_cltv_expiry_delta"],
        "client_trusts_lsp": cfg["client_trusts_lsp"],
    }


def params_fee(ofp, payment_size_msat):
    return opening_fee(
        payment_size_msat, int(ofp["min_fee_msat"]), int(ofp["proportional"])
    )


METHODS = {
    "lsps0.list_protocols": list_protocols,
    "lsps2.get_info": get_info,
    "lsps2.buy": buy,
}


# --- Channel open ----------------------------------------------------------


def fund_zero_conf(peer_id, capacity_sat):
    return plugin.rpc.call(
        "fundchannel",
        {
            "id": peer_id,
            "amount": capacity_sat,
            "announce": False,
            "mindepth": 0,
            "channel_type": [12, 46, 50],
        },
    )


def fails_held_parts(func):
    """Wrap `func(session)`, which holds the session's HTLCs: on an
    unexpected exception, fail the parts still held instead of leaving them
    unanswered until the payment times out."""

    @functools.wraps(func)
    def wrapper(session):
        held = list(session.parts)
        try:
            func(session)
        except Exception as e:
            report_error(func.__name__, e, jit_channel_scid=session.scid)
            with state.lock:
                parts = {id(p): p for p in held + session.parts}.values()
                fail_parts(
                    [p for p in parts if p["request"].state == RequestState.PENDING],
                    "error",
                    TEMPORARY_NODE_FAILURE,
                )
                session.parts = []
                if session.state == "opening":
                    session.state = "collecting"

    return wrapper


def peer_connected(peer_id):
    peers = plugin.rpc.listpeers(peer_id)["peers"]
    return bool(peers) and peers[0]["connected"]


@fails_held_parts
def open_channel(session):
    """Open the JIT channel, run on a worker thread so that the hooks and
    notifications keep flowing while `fundchannel` waits for the peer."""
    cfg = state.config["open"]
    if cfg["behavior"] == "never":
        record("open_skipped", jit_channel_scid=session.scid)
        with state.lock:
            fail_parts(session.parts, "open_skipped")
            session.parts = []
            session.state = "collecting"
        return
    try:
        res = fund_zero_conf(session.peer_id, cfg["capacity_sat"])
    except RpcError as e:
        # bLIP-52: a client that rejects the open with an `error` gets
        # unknown_next_peer; one that disconnects before funding_signed gets
        # temporary_channel_failure, so the payer may retry later. A client
        # that rejects the open stays connected.
        connected = peer_connected(session.peer_id)
        record(
            "open_failed",
            jit_channel_scid=session.scid,
            error=str(e),
            connected=connected,
        )
        with state.lock:
            fail_parts(
                session.parts,
                "open_failed",
                UNKNOWN_NEXT_PEER if connected else TEMPORARY_CHANNEL_FAILURE,
            )
            session.parts = []
            session.state = "collecting"
        return

    channel_id = res["channel_id"]
    channels = plugin.rpc.listpeerchannels(session.peer_id)["channels"]
    channel = next(c for c in channels if c["channel_id"] == channel_id)
    record(
        "open",
        jit_channel_scid=session.scid,
        channel_id=channel_id,
        capacity_sat=cfg["capacity_sat"],
    )
    with state.lock:
        session.channel_id = channel_id
        session.htlc_minimum_msat = int(channel["minimum_htlc_out_msat"])
        if channel_id in state.normal_channels:
            release(session)

    if cfg["behavior"] == "twice":
        try:
            res = fund_zero_conf(session.peer_id, cfg["capacity_sat"])
            record("open", jit_channel_scid=session.scid,
                   channel_id=res["channel_id"],
                   capacity_sat=cfg["capacity_sat"])
        except RpcError as e:
            record("open_failed", jit_channel_scid=session.scid, error=str(e))


@plugin.subscribe("channel_state_changed")
def on_channel_state_changed(channel_state_changed, **kwargs):
    if channel_state_changed["new_state"] != "CHANNELD_NORMAL":
        return
    channel_id = channel_state_changed["channel_id"]
    with state.lock:
        state.normal_channels.add(channel_id)
        for session in state.sessions.values():
            if session.channel_id == channel_id and session.state == "opening":
                release(session)


# --- HTLC interception and forwarding --------------------------------------


def fail_parts(parts, reason, failure_message=UNKNOWN_NEXT_PEER):
    for part in parts:
        record(
            "htlc",
            payment_hash=part["htlc"]["payment_hash"],
            decision="fail",
            reason=reason,
            failure_message=failure_message,
        )
        part["request"].set_result(
            {"result": "fail", "failure_message": failure_message}
        )


def forward_part(session, part, deduction_msat, extra_fee_msat):
    """Forward `part` over the session's channel, `deduction_msat` short of
    its onion amount, with `extra_fee_msat` as extra_fee (None: no TLV)."""
    onion_msat = int(part["onion"]["forward_msat"])
    forward_msat = onion_msat - deduction_msat
    response = {"result": "continue", "forward_to": session.channel_id}
    if deduction_msat:
        response["payload"] = payload_with_amount(
            part["onion"]["payload"], forward_msat
        )
    if extra_fee_msat is not None:
        response["extra_tlvs"] = extra_fee_tlvs(extra_fee_msat)
    record(
        "htlc",
        jit_channel_scid=session.scid,
        payment_hash=part["htlc"]["payment_hash"],
        amount_msat=int(part["htlc"]["amount_msat"]),
        onion_forward_msat=onion_msat,
        forward_msat=forward_msat,
        extra_fee_msat=extra_fee_msat,
        decision="forward",
    )
    part["request"].set_result(response)


def split_fee(amounts, fee_msat, htlc_minimum_msat):
    """Distribute the opening fee over the parts as in the bLIP-52 example
    algorithm. Returns the deduction per part, or None if the parts cannot
    carry the fee while each keeps `htlc_minimum_msat` (and at least 1 msat,
    BOLT 2 forbids zero-amount HTLCs)."""
    floor = max(htlc_minimum_msat, 1)
    deductions = []
    remaining = fee_msat
    for amount in amounts:
        if amount - floor >= remaining:
            deduction = remaining
        else:
            deduction = max(amount - floor, 0)
        deductions.append(deduction)
        remaining -= deduction
    return deductions if remaining == 0 else None


@fails_held_parts
def release(session):
    """Forward the collected parts over the now usable channel. Called with
    the state lock held."""
    session.state = "forwarded"
    parts, session.parts = session.parts, []
    cfg = state.config["htlc"]

    if cfg["behavior"] == "deduct":
        for i, part in enumerate(parts):
            deductions, extra_fees = cfg["deductions"], cfg["extra_fees"]
            deduction = deductions[i] if i < len(deductions) else 0
            if extra_fees is None:
                extra_fee = deduction or None
            else:
                extra_fee = extra_fees[i] if i < len(extra_fees) else None
            forward_part(session, part, deduction, extra_fee)
        return

    if cfg["behavior"] == "forward_subset":
        fail_parts(
            [p for i, p in enumerate(parts) if i not in cfg["parts"]],
            "forward_subset",
        )
        parts = [p for i, p in enumerate(parts) if i in cfg["parts"]]

    forward_with_fee(session, parts, session_fee(session))


def session_fee(session):
    fee_msat = state.config["htlc"]["fee_msat"]
    return session.opening_fee_msat if fee_msat is None else fee_msat


def forward_with_fee(session, parts, fee_msat):
    amounts = [int(p["onion"]["forward_msat"]) for p in parts]
    deductions = split_fee(amounts, fee_msat, session.htlc_minimum_msat)
    if deductions is None:
        fail_parts(parts, "fee_exceeds_parts")
        return
    for part, deduction in zip(parts, deductions):
        forward_part(session, part, deduction, deduction or None)


def var_invoice_fee(session, amount_msat):
    """no-MPP+var-invoice: the opening fee for the first HTLC, whose onion
    amount is the payment size, or None if the LSP must fail it."""
    ofp = session.params
    if not (
        int(ofp["min_payment_size_msat"])
        <= amount_msat
        <= int(ofp["max_payment_size_msat"])
    ):
        return None
    try:
        fee_msat = params_fee(ofp, amount_msat)
    except FeeOverflow:
        return None
    # bLIP-52 requires opening_fee + htlc_minimum_msat <= htlc_value_msat.
    # The channel's htlc_minimum_msat is only known once it is open, and
    # release() checks it then; here use the 1 msat every HTLC needs.
    if fee_msat + 1 > amount_msat:
        return None
    return fee_msat


def seconds_to_expiry(session):
    """Seconds until the session's params expire, by the mock's clock."""
    offset = timedelta(seconds=state.config["htlc"]["clock_offset_seconds"])
    now = datetime.now(timezone.utc) + offset
    return (parse_lsps_datetime(session.params["valid_until"]) - now).total_seconds()


def expired(session):
    """Whether the session's params expired: bLIP-52 opens the channel only
    while the current time is strictly less than valid_until."""
    return seconds_to_expiry(session) <= 0


def expire_held_parts(session):
    """bLIP-52: parts held while waiting for the payment time out at
    valid_until, even if no further part arrives. Called with the state lock
    held."""
    if session.state == "collecting" and session.parts and expired(session):
        fail_parts(session.parts, "expired")
        session.parts = []


def arm_expiry(session):
    """Run `expire_held_parts` at valid_until."""

    def run():
        with state.lock:
            expire_held_parts(session)
            # The clock may have been moved back since.
            if session.state == "collecting" and session.parts:
                arm_expiry(session)

    timer = threading.Timer(max(seconds_to_expiry(session), 0), run)
    timer.daemon = True
    timer.start()


def collected_enough(session):
    if session.payment_size_msat is None:
        # no-MPP+var-invoice: the first part is the payment.
        return True
    total = sum(int(p["onion"]["forward_msat"]) for p in session.parts)
    return total >= session.payment_size_msat


@plugin.async_hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, request, **kwargs):
    scid = onion.get("short_channel_id")
    with state.lock:
        session = state.sessions.get(scid)
        if session is None:
            request.set_result({"result": "continue"})
            return

        part = {"onion": onion, "htlc": htlc, "request": request}
        if session.state == "forwarded":
            # The session is done; the jit_channel_scid is now just another
            # alias of the channel.
            again = state.config["htlc"]["behavior"] == "deduct_again"
            forward_with_fee(session, [part], session_fee(session) if again else 0)
            return

        if session.state == "collecting" and expired(session):
            fail_parts(session.parts + [part], "expired")
            session.parts = []
            return

        # In no-MPP+var-invoice mode the first part opens the channel, so a
        # collecting session has no parts yet.
        if session.payment_size_msat is None and session.state == "collecting":
            fee_msat = var_invoice_fee(session, int(onion["forward_msat"]))
            if fee_msat is None:
                fail_parts([part], "payment_size")
                return
            session.opening_fee_msat = fee_msat

        if not session.parts:
            session.payment_hash = htlc["payment_hash"]
            arm_expiry(session)
        session.parts.append(part)
        if session.state == "collecting" and collected_enough(session):
            session.state = "opening"
            threading.Thread(target=open_channel, args=(session,), daemon=True).start()


@plugin.hook("custommsg", filters=[LSPS0_MESSAGE_TYPE])
def on_custommsg(peer_id, payload, **kwargs):
    raw = bytes.fromhex(payload)
    if int.from_bytes(raw[:2], "big") == LSPS0_MESSAGE_TYPE:
        raw = raw[2:]
        record("rx", peer_id=peer_id, payload=raw.decode("utf-8", "replace"))
        # lightningd treats an error from this hook as fatal.
        try:
            handle_message(peer_id, raw)
        except Exception as e:
            report_error("custommsg", e, peer_id=peer_id)
    return {"result": "continue"}


# --- Test control ----------------------------------------------------------


@plugin.method("lsps2-mock-configure")
def lsps2_mock_configure(config, **kwargs):
    """Replace the mock's config; phases left out use the defaults."""
    new_config = build_config(config)
    with state.lock:
        state.config = new_config
        # The clock may have moved past valid_until.
        for session in state.sessions.values():
            expire_held_parts(session)
    return {"config": new_config}


@plugin.method("lsps2-mock-state")
def lsps2_mock_state(**kwargs):
    """Return config, issued params, sessions and every recorded event."""
    with state.lock:
        return {
            "config": state.config,
            "issued": list(state.issued.values()),
            "sessions": [s.to_json() for s in state.sessions.values()],
            "events": state.events,
        }


@plugin.method("lsps2-mock-send")
def lsps2_mock_send(peer_id, payload, **kwargs):
    """Send `payload` (a string) to `peer_id` as an LSPS0 message, outside
    of any request."""
    send_raw(peer_id, payload.encode())
    return {}


@plugin.async_method("lsps2-mock-open")
def lsps2_mock_open(peer_id, request, capacity_sat=100_000, **kwargs):
    """Open a zero-conf channel to `peer_id` outside of any session."""

    def run():
        try:
            res = fund_zero_conf(peer_id, capacity_sat)
        except RpcError as e:
            request.set_exception(e)
            return
        record("open", jit_channel_scid=None, channel_id=res["channel_id"],
               capacity_sat=capacity_sat)
        request.set_result({"channel_id": res["channel_id"]})

    threading.Thread(target=run, daemon=True).start()


plugin.add_option(
    "lsps2-mock-config",
    "{}",
    "Initial mock config as JSON, see lsps2-mock-configure.",
)


@plugin.init()
def init(options, **kwargs):
    state.config = build_config(json.loads(options["lsps2-mock-config"]))


plugin.run()
