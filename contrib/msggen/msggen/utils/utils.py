import json
from pathlib import Path
import re

from msggen.model import Method, Notification, CompositeField, Service


def load_jsonrpc_method(name, schema_dir: Path):
    """Load a method based on the file naming conventions for the JSON-RPC.
    """
    request, response = load_fields(name, schema_dir)

    # Normalize the method request and response typename so they no
    # longer conflict.
    request.typename += "Request"
    response.typename += "Response"

    return Method(
        name,
        request=request,
        response=response,
    )


def load_jsonrpc_notification(name, schema_dir: Path):
    """Load a notification based on the file naming conventions for the JSON-RPC.
    """
    request, response = load_fields(name, schema_dir)

    return Notification(
        name,
        response=response,
    )


def load_fields(name, schema_dir: Path):
    """Load notification and notification schema from JSON-RPC files.
    """
    base_path = schema_dir

    req_file = base_path / f"{name.lower()}.request.json"
    resp_file = base_path / f"{name.lower()}.schema.json"
    request = CompositeField.from_js(json.load(open(req_file)), path=name)
    response = CompositeField.from_js(json.load(open(resp_file)), path=name)

    return request, response;


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
        "FundChannel",
        # "fundchannel_start",
        # "funderupdate",
        # "getlog",
        "GetRoute",
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
        "SetChannel",
        "SignMessage",
        # "unreserveinputs",
        # "waitblockheight",
        # "ListConfigs",
        # "check",  # No point in mapping this one
        "Stop",
        # "notifications",  # No point in mapping this
        # "help",
    ]
    methods = [load_jsonrpc_method(name, schema_dir=schema_dir) for name in method_names]
    service = Service(name="Node", methods=methods)
    service.includes = ['primitives.proto']  # Make sure we have the primitives included.
    return service


def convert_to_lower_snake(string):
    """Convert a string to lowercase and snakecase.
    """
    return re.sub(r'(?<!^)(?=[A-Z])', '_', string).lower()
