from msggen.model import Method, CompositeField, Service
from msggen.grpc import GrpcGenerator, GrpcConverterGenerator, GrpcUnconverterGenerator, GrpcServerGenerator
from msggen.rust import RustGenerator
from pathlib import Path
import subprocess
import json


# Sometimes we want to rename a method, due to a name clash
method_name_override = {
    "Connect": "ConnectPeer",
}


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
        name=method_name_override.get(name, name),
        request=request,
        response=response,
    )


def load_jsonrpc_service():
    method_names = [
        "Getinfo",
        "ListPeers",
        "ListFunds",
        # "ListConfigs",
        "ListChannels",
        "AddGossip",
        "AutoCleanInvoice",
        "CheckMessage",
        # "check",  # No point in mapping this one
        "Close",
        "Connect",
        "CreateInvoice",
        # "createonion",
        "Datastore",
        # "decodepay",
        # "decode",
        "DelDatastore",
        "DelExpiredInvoice",
        "DelInvoice",
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
        "Invoice",
        # "keysend",
        # "listchannels",
        # "listconfigs",
        "ListDatastore",
        # "listforwards",
        # "listfunds",
        "ListInvoices",
        # "listnodes",
        # "listoffers",
        # "listpays",
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


def gengrpc(service, meta):
    """Load all mapped RPC methods, wrap them in a Service, and split them into messages.
    """
    fname = repo_root() / "cln-grpc" / "proto" / "node.proto"
    dest = open(fname, "w")
    GrpcGenerator(dest, meta).generate(service)

    fname = repo_root() / "cln-grpc" / "src" / "convert.rs"
    dest = open(fname, "w")
    GrpcConverterGenerator(dest).generate(service)
    GrpcUnconverterGenerator(dest).generate(service)

    fname = repo_root() / "cln-grpc" / "src" / "server.rs"
    dest = open(fname, "w")
    GrpcServerGenerator(dest).generate(service)


def genrustjsonrpc(service):
    fname = repo_root() / "cln-rpc" / "src" / "model.rs"
    dest = open(fname, "w")
    RustGenerator(dest).generate(service)


def load_msggen_meta():
    meta = json.load(open('.msggen.json', 'r'))
    return meta


def write_msggen_meta(meta):
    with open('.msggen.json', 'w') as f:
        json.dump(meta, f, sort_keys=True, indent=4)


def run():
    service = load_jsonrpc_service()
    meta = load_msggen_meta()
    gengrpc(service, meta)
    genrustjsonrpc(service)
    write_msggen_meta(meta)


if __name__ == "__main__":
    run()
