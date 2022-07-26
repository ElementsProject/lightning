import json
import os
from msggen.gen.grpc import GrpcGenerator, GrpcConverterGenerator, GrpcUnconverterGenerator, GrpcServerGenerator
from msggen.gen.grpc2py import Grpc2PyGenerator
from msggen.gen.rust import RustGenerator
from msggen.gen.generator import GeneratorChain
from msggen.utils import repo_root, load_jsonrpc_service


def add_handler_gen_grpc(generator_chain: GeneratorChain, meta):
    """Load all mapped RPC methods, wrap them in a Service, and split them into messages.
    """
    fname = repo_root() / "cln-grpc" / "proto" / "node.proto"
    dest = open(fname, "w")
    generator_chain.add_generator(GrpcGenerator(dest, meta))

    fname = repo_root() / "cln-grpc" / "src" / "convert.rs"
    dest = open(fname, "w")
    generator_chain.add_generator(GrpcConverterGenerator(dest))
    generator_chain.add_generator(GrpcUnconverterGenerator(dest))

    fname = repo_root() / "cln-grpc" / "src" / "server.rs"
    dest = open(fname, "w")
    generator_chain.add_generator(GrpcServerGenerator(dest))


def add_handler_get_grpc2py(generator_chain: GeneratorChain):
    fname = repo_root() / "contrib" / "pyln-testing" / "pyln" / "testing" / "grpc2py.py"
    dest = open(fname, "w")
    generator_chain.add_generator(Grpc2PyGenerator(dest))


def add_handler_gen_rust_jsonrpc(generator_chain: GeneratorChain):
    fname = repo_root() / "cln-rpc" / "src" / "model.rs"
    dest = open(fname, "w")
    generator_chain.add_generator(RustGenerator(dest))


def load_msggen_meta():
    meta = json.load(open('.msggen.json', 'r'))
    return meta


def write_msggen_meta(meta):
    pid = os.getpid()
    with open(f'.msggen.json.tmp.{pid}', 'w') as f:
        json.dump(meta, f, sort_keys=True, indent=4)
    os.rename(f'.msggen.json.tmp.{pid}', '.msggen.json')


def run():
    service = load_jsonrpc_service()
    meta = load_msggen_meta()
    generator_chain = GeneratorChain()

    add_handler_gen_grpc(generator_chain, meta)
    add_handler_gen_rust_jsonrpc(generator_chain)
    add_handler_get_grpc2py(generator_chain)

    generator_chain.generate(service)

    write_msggen_meta(meta)


if __name__ == "__main__":
    run()
