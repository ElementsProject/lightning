import subprocess
import json
from pathlib import Path

from msggen.model import Method, CompositeField, Service

# Sometimes we want to rename a method, due to a name clash
# FIXME: need to be generalized?
method_name_override = {
    "Connect": "ConnectPeer",
}


def repo_root():
    path = subprocess.check_output(["git", "rev-parse", "--show-toplevel"])
    return Path(path.strip().decode('UTF-8'))


def load_jsonrpc_method(name, schema_dir: str = None):
    """Load a method based on the file naming conventions for the JSON-RPC.
    """
    if schema_dir is None:
        base_path = (repo_root() / "doc" / "schemas").resolve()
    else:
        base_path = schema_dir
    req_file = base_path / f"{name.lower()}.request.json"
    resp_file = base_path / f"{name.lower()}.schema.json"
    request = CompositeField.from_js(json.load(open(req_file)), path=name)
    response = CompositeField.from_js(json.load(open(resp_file)), path=name)

    # Normalize the method request and response typename so they no
    # longer conflict.
    request.typename += "Request"
    response.typename += "Response"

    return Method(
        name=method_name_override.get(name, name),
        request=request,
        response=response,
    )


def load_jsonrpc_service(schema_dir: str = None):
    method_names = [
        "Getinfo",
        "ListPeers",
        "ListFunds",
        "SendPay",
        "ListChannels",
        "AddGossip",
        "AutoCleanInvoice",
        "CheckMessage",
        "Close",
        "Connect",
        "CreateInvoice",
        "Datastore",
        "CreateOnion",
        "DelDatastore",
        "DelExpiredInvoice",
        "DelInvoice",
        "Invoice",
        "ListDatastore",
        "ListInvoices",
        "SendOnion",
        "ListSendPays",
        "ListTransactions",
        "Pay",
        "ListNodes",
        "WaitAnyInvoice",
        "WaitInvoice",
        "WaitSendPay",
        "NewAddr",
        "Withdraw",
        "KeySend",
        "FundPsbt",
        "SendPsbt",
        "SignPsbt",
        "UtxoPsbt",
        "TxDiscard",
        "TxPrepare",
        "TxSend",
        # "decodepay",
        # "decode",
        # "delpay",
        # "disableoffer",
        "Disconnect",
        "Feerates",
        # "fetchinvoice",
        # "fundchannel_cancel",
        # "fundchannel_complete",
        # "fundchannel",
        # "fundchannel_start",
        # "funderupdate",
        # "getlog",
        "GetRoute",
        # "getsharedsecret",
        "ListForwards",
        # "listoffers",
        "ListPays",
        # "multifundchannel",
        # "multiwithdraw",
        # "offerout",
        # "offer",
        # "openchannel_abort",
        # "openchannel_bump",
        # "openchannel_init",
        # "openchannel_signed",
        # "openchannel_update",
        # "parsefeerate",
        "Ping",
        # "plugin",
        # "reserveinputs",
        # "sendcustommsg",
        # "sendinvoice",
        # "sendonionmessage",
        # "setchannelfee",
        "SignMessage",
        # "unreserveinputs",
        # "waitblockheight",
        # "ListConfigs",
        # "check",  # No point in mapping this one
        # "Stop",  # Breaks a core assumption (root is an object) can't map unless we change this
        # "notifications",  # No point in mapping this
        # "help",
    ]
    methods = [load_jsonrpc_method(name, schema_dir=schema_dir) for name in method_names]
    service = Service(name="Node", methods=methods)
    service.includes = ['primitives.proto']  # Make sure we have the primitives included.
    return service
