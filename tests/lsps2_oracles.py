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
import os
from datetime import datetime, timezone


def _load_plugin_module(name):
    # tests/plugins is not a package.
    path = os.path.join(os.path.dirname(__file__), "plugins", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lsps2_mock_fee = _load_plugin_module("lsps2_mock_fee")


class Observation:
    """What the client and the mock service on the LSP did, as plain data,
    so that checks can also be fed by hand."""

    def __init__(self, client_id, lsp_id, mock_state, invoices, channels):
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
        return cls(
            client.info["id"],
            lsp.info["id"],
            mock_state,
            invoices,
            channels,
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
