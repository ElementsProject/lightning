import json
from pathlib import Path

from msggen.model import Method, CompositeField, Service


def load_jsonrpc_method(name, schema_dir: Path):
    """Load a method based on the file naming conventions for the JSON-RPC.
    """
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
        name,
        request=request,
        response=response,
    )


def load_jsonrpc_service(schema_dir: str):
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
        "DatastoreUsage",
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
        "ListPeerChannels",
        "ListClosedChannels",
        "DecodePay",
        "Decode",
        # "delpay",
        # "disableoffer",
        "Disconnect",
        "Feerates",
        "FetchInvoice",
        # "fundchannel_cancel",
        # "fundchannel_complete",
        "FundChannel",
        # "fundchannel_start",
        # "funderupdate",
        # "getlog",
        "GetRoute",
        "ListForwards",
        # "listoffers",
        "ListPays",
        "ListHtlcs",
        # "multifundchannel",
        # "multiwithdraw",
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
        "SendCustomMsg",
        # "sendinvoice",
        # "sendonionmessage",
        "SetChannel",
        "SignInvoice",
        "SignMessage",
        # "unreserveinputs",
        "WaitBlockHeight",
        # "ListConfigs",
        # "check",  # No point in mapping this one
        "Stop",
        # "notifications",  # No point in mapping this
        # "help",
        "PreApproveKeysend",
        "PreApproveInvoice",
        "StaticBackup",
    ]
    methods = [load_jsonrpc_method(name, schema_dir=schema_dir) for name in method_names]
    service = Service(name="Node", methods=methods)
    service.includes = ['primitives.proto']  # Make sure we have the primitives included.
    return service
