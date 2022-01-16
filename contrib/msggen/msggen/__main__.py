from msggen.model import Method, CompositeField, Service
from msggen.grpc import GrpcGenerator, GrpcConverterGenerator, GrpcUnconverterGenerator
from msggen.rust import RustGenerator
from pathlib import Path
import subprocess
import json


def repo_root():
    path = subprocess.check_output(["git", "rev-parse", "--show-toplevel"])
    return Path(path.strip().decode('UTF-8'))


def load_jsonrpc_method(name):
    """Load a method based on the file naming conventions for the JSON-RPC.
    """
    base_path = (repo_root() / "doc" / "schemas").resolve()
    req_file = base_path / f"{name.lower()}.request.json"
    resp_file = base_path / f"{name.lower()}.schema.json"
    request = CompositeField.from_js(json.load(open(req_file)), path=name)
    response = CompositeField.from_js(json.load(open(resp_file)), path=name)

    # Normalize the method request and response typename so they no
    # longer conflict.
    request.typename += "Request"
    response.typename += "Response"

    return Method(
        name=name,
        request=request,
        response=response,
    )


def load_jsonrpc_service():
    method_names = [
        "Getinfo",
        # "ListPeers",
        "ListFunds",
        # "ListConfigs",
        "ListChannels",
        "AddGossip",
        "AutoCleanInvoice",
        "CheckMessage",
        # "check",  # No point in mapping this one
        "Close",
        # "connect",
        # "createinvoice",
        # "createonion",
        # "datastore",
        # "decodepay",
        # "decode",
        # "deldatastore",
        # "delexpiredinvoice",
        # "delinvoice",
        # "delpay",
        # "disableoffer",
        # "disconnect",
        # "feerates",
        # "fetchinvoice",
        # "fundchannel_cancel",
        # "fundchannel_complete",
        # "fundchannel",
        # "fundchannel_start",
        # "funderupdate",
        # "fundpsbt",
        # "getinfo",
        # "getlog",
        # "getroute",
        # "getsharedsecret",
        # "help",
        # "invoice",
        # "keysend",
        # "listchannels",
        # "listconfigs",
        # "listdatastore",
        # "listforwards",
        # "listfunds",
        # "listinvoices",
        # "listnodes",
        # "listoffers",
        # "listpays",
        # "listpeers",
        # "listsendpays",
        # "listtransactions",
        # "multifundchannel",
        # "multiwithdraw",
        # "newaddr",
        # "notifications",
        # "offerout",
        # "offer",
        # "openchannel_abort",
        # "openchannel_bump",
        # "openchannel_init",
        # "openchannel_signed",
        # "openchannel_update",
        # "parsefeerate",
        # "pay",
        # "ping",
        # "plugin",
        # "reserveinputs",
        # "sendcustommsg",
        # "sendinvoice",
        # "sendonionmessage",
        # "sendonion",
        # "sendpay",
        # "sendpsbt",
        # "setchannelfee",
        # "signmessage",
        # "signpsbt",
        # "stop",
        # "txdiscard",
        # "txprepare",
        # "txsend",
        # "unreserveinputs",
        # "utxopsbt",
        # "waitanyinvoice",
        # "waitblockheight",
        # "waitinvoice",
        # "waitsendpay",
        # "withdraw",
    ]
    methods = [load_jsonrpc_method(name) for name in method_names]
    service = Service(name="Node", methods=methods)
    service.includes = ['primitives.proto']  # Make sure we have the primitives included.
    return service


def gengrpc(service):
    """Load all mapped RPC methods, wrap them in a Service, and split them into messages.
    """
    fname = repo_root() / "cln-grpc" / "proto" / "node.proto"
    dest = open(fname, "w")
    GrpcGenerator(dest).generate(service)

    fname = repo_root() / "cln-grpc" / "src" / "convert.rs"
    dest = open(fname, "w")
    GrpcConverterGenerator(dest).generate(service)
    GrpcUnconverterGenerator(dest).generate(service)


def genrustjsonrpc(service):
    fname = repo_root() / "cln-rpc" / "src" / "model.rs"
    dest = open(fname, "w")
    RustGenerator(dest).generate(service)


def run():
    service = load_jsonrpc_service()
    gengrpc(service)
    genrustjsonrpc(service)


if __name__ == "__main__":
    run()
