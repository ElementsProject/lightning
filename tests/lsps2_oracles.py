"""Oracles for the LSPS2 client tests.

Whatever the mock LSPS2 service (plugins/lsps2_mock.py) does, a test ends
by checking these invariants on what the client did:

- Amount: no preimage for less than the invoice amount minus the opening
  fee computed from the chosen params; the fee is deducted only once per
  session.
- Identity: channels and HTLCs are accepted only from the session's LSP
  and only on the promised SCID.
- Params and deadlines: expired, contradictory or modified params never
  lead to a payment.
- Robustness: no LSP input crashes the client or leaves it hanging or
  retrying without bound.

The mock records what it received, issued, sent and forwarded; the client
is observed through its invoices, channels and log. Each check has an ID
such as "amount.received", and `check_oracles` fails with every violation
it finds.
"""

import importlib.util
import json
import math
import os
import re
from datetime import datetime, timezone

from pyln.testing.utils import wait_for


def _load_plugin_module(name):
    # tests/plugins is not a package.
    path = os.path.join(os.path.dirname(__file__), "plugins", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lsps2_mock_fee = _load_plugin_module("lsps2_mock_fee")

# bLIP-52 lets the LSP send promises of up to 512 bytes, in printable ASCII
# that needs no escaping in JSON; the client aborts on anything else.
MAX_PROMISE_BYTES = 512

# LSPS requests a client may send in one test; a retry loop exceeds it.
MAX_LSPS_REQUESTS = 20
LSPS_CLIENT_PLUGIN = "cln-lsps-client"
CRASH_LOG = re.compile(LSPS_CLIENT_PLUGIN + r".*(panicked|Killing plugin)")


class Observation:
    """What the client and the mock service on the LSP did, as plain data,
    so that checks can also be fed by hand."""

    def __init__(
        self,
        client_id,
        lsp_id,
        mock_state,
        invoices,
        channels,
        plugins,
        crash_logs,
    ):
        self.client_id = client_id
        self.lsp_id = lsp_id
        self.issued = mock_state["issued"]
        self.sessions = [
            s for s in mock_state["sessions"] if s["peer_id"] == client_id
        ]
        self.events = mock_state["events"]
        # listinvoices entries, with the decoded bolt11 under "decoded".
        self.invoices = invoices
        # listpeerchannels entries, with the funding tx's confirmations
        # under "confirmations".
        self.channels = channels
        # Names of the client's active plugins.
        self.plugins = plugins
        # Client log lines showing the LSPS client crashed.
        self.crash_logs = crash_logs

    @classmethod
    def from_nodes(cls, client, lsp):
        mock_state = lsp.rpc.call("lsps2-mock-state")
        # How each forward ended, so that parts the client failed don't
        # count towards the payment.
        statuses = {
            (f["in_channel"], f.get("in_htlc_id")): f["status"]
            for f in lsp.rpc.listforwards()["forwards"]
        }
        for e in mock_state["events"]:
            if e["type"] == "htlc" and e["decision"] == "forward":
                e["status"] = statuses.get((e["in_channel"], e["in_htlc_id"]))
        invoices = []
        for inv in client.rpc.listinvoices()["invoices"]:
            if "bolt11" in inv:
                invoices.append({**inv, "decoded": client.rpc.decode(inv["bolt11"])})
        channels = [
            {**c, "confirmations": _confirmations(client, c.get("funding_txid"))}
            for c in client.rpc.listpeerchannels()["channels"]
        ]
        plugins = [
            os.path.basename(p["name"])
            for p in client.rpc.plugin("list")["plugins"]
            if p["active"]
        ]
        return cls(
            client.info["id"],
            lsp.info["id"],
            mock_state,
            invoices,
            channels,
            plugins,
            [line for line in client.daemon.logs if CRASH_LOG.search(line)],
        )

    def paid_invoices(self):
        return [i for i in self.invoices if i["status"] == "paid"]

    def forwards(self, payment_hash):
        """The parts of a payment the mock forwarded to the client and the
        client settled."""
        return [
            e
            for e in self.events
            if e["type"] == "htlc"
            and e["decision"] == "forward"
            and e["status"] == "settled"
            and e["payment_hash"] == payment_hash
        ]

    def session(self, **match):
        """The client's session whose fields equal `match`, or None."""
        for s in self.sessions:
            if all(s.get(k) == v for k, v in match.items()):
                return s
        return None

    def messages(self, kind):
        """(time, message) for each JSON object in the mock's `kind` events
        with the client: "rx" received from it, "tx" sent to it."""
        out = []
        for e in self.events:
            if e["type"] != kind or e["peer_id"] != self.client_id:
                continue
            try:
                msg = json.loads(e["payload"])
            except ValueError:
                continue
            if isinstance(msg, dict):
                out.append((e["time"], msg))
        return out

    def buy_result(self, scid):
        """The first buy result the client was sent for `scid`."""
        for _, msg in self.messages("tx"):
            result = msg.get("result")
            if isinstance(result, dict) and result.get("jit_channel_scid") == scid:
                return result
        return None

    def lsps2_invoices(self):
        """(invoice, session) for each invoice with a route hint on a
        jit_channel_scid of the client's sessions."""
        out = []
        for inv in self.invoices:
            seen = []
            for route in inv["decoded"].get("routes", []):
                for hop in route:
                    session = self.session(jit_channel_scid=hop["short_channel_id"])
                    if session is not None and session not in seen:
                        seen.append(session)
                        out.append((inv, session))
        return out

    def channel_ids(self):
        """Every SCID and alias the client knows for its channels."""
        ids = set()
        for c in self.channels:
            ids.add(c.get("short_channel_id"))
            ids.update(c.get("alias", {}).values())
        ids.discard(None)
        return ids


def _confirmations(node, txid):
    if txid is None:
        return 0
    try:
        tx = node.bitcoin.rpc.getrawtransaction(txid, True)
    except Exception:
        # Not broadcast.
        return 0
    return tx.get("confirmations", 0)


def opening_fee(params, payment_size_msat):
    """The opening fee for `params` (as sent by the LSP), or None if it
    cannot be computed."""
    try:
        return lsps2_mock_fee.opening_fee(
            payment_size_msat, int(params["min_fee_msat"]), int(params["proportional"])
        )
    except (lsps2_mock_fee.FeeOverflow, KeyError, TypeError, ValueError):
        return None


def parse_lsps_datetime(s):
    dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    return dt.replace(tzinfo=timezone.utc)


def parse_msat(v):
    """An LSPS0.msat (a string of decimal digits) as int, or None."""
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


CHECKS = []


def check(f):
    """Register a check: a function of an Observation yielding
    (check_id, message) for each violation."""
    CHECKS.append(f)
    return f


class OracleViolation(AssertionError):
    pass


def violations(obs, waive=()):
    return [(cid, msg) for f in CHECKS for cid, msg in f(obs) if cid not in waive]


def check_oracles(client, lsp, waive=()):
    """Check the oracles on what `client` did with the mock service on `lsp`;
    `waive` lists check IDs to skip."""

    def settled():
        channels = client.rpc.listpeerchannels()["channels"]
        return not any(c.get("htlcs") for c in channels)

    # A test waiving robustness.hanging expects HTLCs to stay held.
    if "robustness.hanging" not in waive:
        try:
            wait_for(settled)
        except ValueError:
            # Reported as hanging.
            pass
    found = violations(Observation.from_nodes(client, lsp), waive)
    if found:
        raise OracleViolation(
            "\n".join(f"{cid}: {msg}" for cid, msg in found)
        )


# --- Amount ----------------------------------------------------------------


@check
def check_amount(obs):
    """A paid invoice received at least what was paid for minus what it
    owes. The payment that opened the channel owes the session's opening
    fee on the payment size (the onion amount in no-MPP+var-invoice mode);
    later payments owe nothing on their invoice amount (or onion amount)."""
    for inv in obs.paid_invoices():
        forwards = obs.forwards(inv["payment_hash"])
        if not forwards:
            # Not paid through the mock.
            continue
        onion_msat = sum(f["onion_forward_msat"] for f in forwards)
        session = obs.session(payment_hash=inv["payment_hash"])
        if session is None:
            expected_msat = inv.get("amount_msat", onion_msat)
            fee_msat = 0
        else:
            # Not the invoice's amount: the client keeps a copy of the
            # invoice reduced by the fee.
            expected_msat = session["payment_size_msat"] or onion_msat
            fee_msat = opening_fee(session["opening_fee_params"], expected_msat)
        if fee_msat is None:
            yield "amount.received", (
                f"invoice {inv['label']!r} paid although the opening fee "
                f"cannot be computed"
            )
        elif inv["amount_received_msat"] < expected_msat - fee_msat:
            yield "amount.received", (
                f"invoice {inv['label']!r} received "
                f"{inv['amount_received_msat']} msat, less than "
                f"{expected_msat} - {fee_msat} msat"
            )


@check
def check_balance(obs):
    """The client's balance in channels it did not open does not exceed
    what its paid invoices received: nothing was released outside an
    invoice."""
    held_msat = sum(c["to_us_msat"] for c in obs.channels if c["opener"] == "remote")
    received_msat = sum(i["amount_received_msat"] for i in obs.paid_invoices())
    if held_msat > received_msat:
        yield "amount.balance", (
            f"client holds {held_msat} msat in channels but its paid "
            f"invoices received {received_msat} msat"
        )


# --- Identity --------------------------------------------------------------


@check
def check_route_hint(obs):
    """An invoice routes only through channels the client has, or through
    the LSP on a jit_channel_scid the LSP issued to this client; an LSPS2
    invoice has exactly that one single-hop route hint."""
    channel_ids = obs.channel_ids()
    for inv in obs.invoices:
        routes = inv["decoded"].get("routes", [])
        hops = [hop for route in routes for hop in route]
        sessions = [obs.session(jit_channel_scid=h["short_channel_id"]) for h in hops]
        if any(sessions) and len(hops) != 1:
            yield "identity.route_hint", (
                f"invoice {inv['label']!r} has more than the one route "
                f"hint to the LSP"
            )
        for hop, session in zip(hops, sessions):
            if session is not None:
                if hop["pubkey"] != obs.lsp_id:
                    yield "identity.route_hint", (
                        f"invoice {inv['label']!r} routes through "
                        f"{hop['pubkey']} instead of the LSP"
                    )
            elif hop["short_channel_id"] not in channel_ids:
                yield "identity.route_hint", (
                    f"invoice {inv['label']!r} routes through "
                    f"{hop['short_channel_id']}, which is neither a channel "
                    f"of the client nor issued by the LSP"
                )


@check
def check_zero_conf_channel(obs):
    """A channel the client uses before its funding confirms is the one the
    LSP opened for one of this client's sessions."""
    session_channels = {s["channel_id"] for s in obs.sessions if s["channel_id"]}
    for c in obs.channels:
        if c["state"] != "CHANNELD_NORMAL" or c["confirmations"] > 0:
            continue
        if c["peer_id"] != obs.lsp_id or c["channel_id"] not in session_channels:
            yield "identity.zero_conf_channel", (
                f"client uses unconfirmed channel {c['channel_id']} from "
                f"{c['peer_id']}, which no session opened"
            )


# --- Params and deadlines --------------------------------------------------


def promise_ok(promise):
    return (
        isinstance(promise, str)
        and len(promise.encode()) <= MAX_PROMISE_BYTES
        and all(0x20 <= ord(c) <= 0x7E and c not in '"\\' for c in promise)
    )


@check
def check_buy_params(obs):
    """The client buys only with params the LSP issued, unchanged, before
    they expire, and consistent."""
    for time, req in obs.messages("rx"):
        if req.get("method") != "lsps2.buy":
            continue
        if not isinstance(req.get("params"), dict):
            continue
        params = req["params"]
        ofp = params.get("opening_fee_params")
        if ofp not in obs.issued:
            yield "params.modified", "client bought with params the LSP did not issue"
            continue

        try:
            valid_until = parse_lsps_datetime(ofp["valid_until"])
            expired = valid_until <= parse_lsps_datetime(time)
        except (KeyError, TypeError, ValueError):
            expired = True
        if expired:
            yield "params.expired", (
                f"client bought with params valid until "
                f"{ofp.get('valid_until')!r}"
            )

        min_msat = parse_msat(ofp.get("min_payment_size_msat"))
        max_msat = parse_msat(ofp.get("max_payment_size_msat"))
        size_msat = parse_msat(params.get("payment_size_msat"))
        if min_msat is None or max_msat is None or min_msat > max_msat:
            yield "params.contradictory", "client bought with unusable size limits"
        elif "payment_size_msat" not in params:
            pass
        elif size_msat is None or not min_msat <= size_msat <= max_msat:
            yield "params.contradictory", "client bought a size outside the limits"
        else:
            fee_msat = opening_fee(ofp, size_msat)
            if fee_msat is None or fee_msat >= size_msat:
                yield "params.contradictory", "client bought a size the fee eats up"

        if not promise_ok(ofp.get("promise")):
            yield "params.promise", "client bought with an invalid promise"


@check
def check_invoice(obs):
    """An LSPS2 invoice follows the buy result and the params: the LSP's
    cltv delta is in the route hint with zero fees, the invoice expires by
    valid_until, and its amount is the payment size."""
    for inv, session in obs.lsps2_invoices():
        result = obs.buy_result(session["jit_channel_scid"]) or {}
        delta = result.get("lsp_cltv_expiry_delta")
        for route in inv["decoded"]["routes"]:
            for hop in route:
                fees = (hop["fee_base_msat"], hop["fee_proportional_millionths"])
                if hop["cltv_expiry_delta"] != delta or fees != (0, 0):
                    yield "params.invoice", (
                        f"invoice {inv['label']!r} route hint does not match "
                        f"the buy result"
                    )

        # Invoice timestamps (BOLT 11) have one-second resolution.
        params = session["opening_fee_params"]
        valid_until = parse_lsps_datetime(params["valid_until"])
        if inv["expires_at"] > math.ceil(valid_until.timestamp()):
            yield "params.invoice", (
                f"invoice {inv['label']!r} expires after the params' valid_until"
            )

        # The client replaces the invoice it hands out by a copy for the
        # payment size minus the fee, which the reduced HTLCs pay.
        size_msat = session["payment_size_msat"]
        if size_msat is None:
            amounts = [None]
        else:
            amounts = [size_msat, size_msat - (opening_fee(params, size_msat) or 0)]
        if inv["decoded"].get("amount_msat") not in amounts:
            yield "params.invoice", (
                f"invoice {inv['label']!r} amount is not the payment size bought"
            )


# --- Robustness ------------------------------------------------------------


@check
def check_crash(obs):
    """The LSPS client plugin is still running and never crashed."""
    if LSPS_CLIENT_PLUGIN not in obs.plugins:
        yield "robustness.crash", f"{LSPS_CLIENT_PLUGIN} is not running"
    for line in obs.crash_logs:
        yield "robustness.crash", line


@check
def check_hanging(obs):
    """No HTLC is left pending in the client's channels."""
    for c in obs.channels:
        if c.get("htlcs"):
            yield "robustness.hanging", (
                f"{len(c['htlcs'])} HTLCs pending in channel {c['channel_id']}"
            )


@check
def check_retry_storm(obs):
    """The client sent a bounded number of LSPS requests."""
    requests = [m for _, m in obs.messages("rx") if "method" in m]
    if len(requests) > MAX_LSPS_REQUESTS:
        yield "robustness.retry_storm", f"client sent {len(requests)} LSPS requests"
