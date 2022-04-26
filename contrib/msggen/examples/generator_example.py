#! /usr/bin/python3
"""
Example of usage msggen module.

This example introduces a fake generator to understand how the
package works, If you would like to see a real generator example
try to see the Rust generator in the `msggen/gen/rust.py`

author: https://github.com/vincenzopalazzo
"""
from msggen.gen.generator import GeneratorChain, IGenerator
from msggen import Service
from msggen.utils import load_jsonrpc_service


class MonkylangGen(IGenerator):
    """This is the custom generator that implements a monkylang generator
     that uses the interface handler IGenerator."""

    def generate(self, service: Service):
        self.write('println("Monky")')


def register_monkylang_gen(generator_chain: GeneratorChain):
    """Helper function to register the custom generator, and
    load the correct path of the json schema."""
    file = '<your_path_of_result>'
    dest = open(file, 'w')
    generator_chain.add_generator(MonkylangGen(dest))


if __name__ == '__main__':
    schema_dir = '<path_of_json_schema_dir>'
    service = load_jsonrpc_service(schema_dir=schema_dir)
    generator_chain = GeneratorChain()
    register_monkylang_gen(generator_chain)
    generator_chain.generate(service)
