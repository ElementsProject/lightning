#!/usr/bin/env python3
"""
Zero‑conf LSPS2 mock
====================

• On the **first incoming HTLC**, call `connect` and `fundchannel` with **zeroconf** to a configured peer.
• **Hold all HTLCs** until the channel reports `CHANNELD_NORMAL`, then **continue** them all.
• After the channel is ready, future HTLCs are continued immediately.
"""

import threading
import time
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from pyln.client import Plugin
from pyln.proto.onion import TlvPayload


plugin = Plugin()


@plugin.method("lsps2-policy-getpolicy")
def lsps2_policy_getpolicy(request):
    """Returns an opening fee menu for the LSPS2 plugin."""
    now = datetime.now(timezone.utc)

    # Is ISO 8601 format "YYYY-MM-DDThh:mm:ss.uuuZ"
    valid_until = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    return {
        "policy_opening_fee_params_menu": [
            {
                "min_fee_msat": "1000000",
                "proportional": 0,
                "valid_until": valid_until,
                "min_lifetime": 2000,
                "max_client_to_self_delay": 2016,
                "min_payment_size_msat": "1000",
                "max_payment_size_msat": "100000000",
            },
        ]
    }


@plugin.method("lsps2-policy-getchannelcapacity")
def lsps2_policy_getchannelcapacity(
    request, init_payment_size, scid, opening_fee_params
):
    """Returns an opening fee menu for the LSPS2 plugin."""
    return {"channel_capacity_msat": 100000000}


TLV_OPENING_FEE = 65537


@dataclass
class Held:
    htlc: dict
    onion: dict
    event: threading.Event = field(default_factory=threading.Event)
    response: Optional[dict] = None


@dataclass
class State:
    target_peer: Optional[str] = None
    channel_cap: Optional[int] = None
    opening_fee_msat: Optional[int] = None
    pending: Dict[str, Held] = field(default_factory=dict)
    funding_started: bool = False
    channel_ready: bool = False
    channel_id_hex: Optional[str] = None
    fee_remaining_msat: int = 0
    worker_thread: Optional[threading.Thread] = None
    lock: threading.Lock = field(default_factory=threading.Lock)


state = State()


def _key(h: dict) -> str:
    return f"{h.get('id', '?')}:{h.get('payment_hash', '?')}"


def _ensure_zero_conf_channel(peer_id: str, capacity: int) -> bool:
    plugin.log(f"fundchannel zero-conf to {peer_id} for {capacity} sat...")
    res = plugin.rpc.fundchannel(
        peer_id,
        capacity,
        announce=False,
        mindepth=0,
        channel_type=[12, 46, 50],
    )
    plugin.log(f"got channel response {res}")
    state.channel_id_hex = res["channel_id"]

    for _ in range(120):
        channels = plugin.rpc.listpeerchannels(peer_id)["channels"]
        for c in channels:
            if c.get("state") == "CHANNELD_NORMAL":
                plugin.log("zero-conf channel is NORMAL; releaseing HTLCs")
                return True
        time.sleep(1)
    return False


def _modify_payload_and_build_response(held: Held):
    amt_msat = int(held.htlc.get("amount_msat", 0))
    fee_applied = 0
    if state.fee_remaining_msat > 0:
        fee_applied = min(state.fee_remaining_msat, max(amt_msat - 1, 0))
        state.fee_remaining_msat -= fee_applied
    forward_msat = max(1, amt_msat - fee_applied)

    payload = None
    extra = None
    if amt_msat != forward_msat:
        amt_byte = struct.pack("!Q", forward_msat)
        while len(amt_byte) > 1 and amt_byte[0] == 0:
            amt_byte = amt_byte[1:]
        payload = TlvPayload().from_hex(held.onion["payload"])
        p = TlvPayload()
        p.add_field(2, amt_byte)
        p.add_field(4, payload.get(4).value)
        p.add_field(6, payload.get(6).value)
        payload = p.to_bytes(include_prefix=False)

        amt_byte = fee_applied.to_bytes(8, "big")
        e = TlvPayload()
        e.add_field(TLV_OPENING_FEE, amt_byte)
        extra = e.to_bytes(include_prefix=False)

    resp = {"result": "continue"}
    if payload:
        resp["payload"] = payload.hex()
    if extra:
        resp["extra_tlvs"] = extra.hex()
    if state.channel_id_hex:
        resp["forward_to"] = state.channel_id_hex
    return resp


def _release_all_locked():
    # called with state.lock held
    items = list(state.pending.items())
    state.pending.clear()
    for _k, held in items:
        if held.response is None:
            held.response = _modify_payload_and_build_response(held)
        held.event.set()


def _worker():
    plugin.log("collecting htlcs and fund channel...")
    with state.lock:
        peer = state.target_peer
        cap = state.channel_cap
        fee = state.opening_fee_msat
    if not peer or not cap or not fee:
        with state.lock:
            _release_all_locked()
        return

    ok = _ensure_zero_conf_channel(peer, cap)
    with state.lock:
        state.channel_ready = ok
        state.fee_remaining_msat = fee if ok else 0
        _release_all_locked()


@plugin.method("setuplsps2service")
def setuplsps2service(plugin, peer_id, channel_cap, opening_fee_msat):
    state.target_peer = peer_id
    state.channel_cap = channel_cap
    state.opening_fee_msat = opening_fee_msat


@plugin.async_hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, request, plugin, **kwargs):
    key = _key(htlc)

    with state.lock:
        if state.channel_ready:
            held_now = Held(htlc=htlc, onion=onion)
            resp = _modify_payload_and_build_response(held_now)
            request.set_result(resp)
            return

        if not state.funding_started:
            state.funding_started = True
            state.worker_thread = threading.Thread(target=_worker, daemon=True)
            state.worker_thread.start()

        # enqueue and block until the worker releases us
        held = Held(htlc=htlc, onion=onion)
        state.pending[key] = held

    held.event.wait()
    request.set_result(held.response)


if __name__ == "__main__":
    plugin.run()
