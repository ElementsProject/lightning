from .model import Method, CompositeField, Service
from .grpc import GrpcGenerator
from pathlib import Path
import subprocess
import json
import io


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

    return Method(
        name=name,
        request=request,
        response=response,
    )


def load_jsonrpc_service():
    method_names = ["Getinfo", "ListPeers"]
    methods = [load_jsonrpc_method(name) for name in method_names]
    service = Service(name="Node", methods=methods)
    service.includes = ['primitives.proto']  # Make sure we have the primitives included.
    return service


def gengrpc():
    """Load all mapped RPC methods, wrap them in a Service, and split them into messages.
    """
    service = load_jsonrpc_service()
    dest = io.StringIO()
    GrpcGenerator(dest).generate(service)
    print(dest.getvalue())


def run():
    gengrpc()


if __name__ == "__main__":
    run()
