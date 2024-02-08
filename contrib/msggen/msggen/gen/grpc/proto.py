# A grpc model
from typing import TextIO, List, Dict, Any
from textwrap import dedent
import logging

from msggen.gen import IGenerator
from msggen.gen.grpc.util import typemap, method_name_overrides
from msggen.model import (
    ArrayField,
    Field,
    CompositeField,
    EnumField,
    PrimitiveField,
    Service,
    MethodName,
    TypeName,
)


class GrpcGenerator(IGenerator):
    """A generator that generates protobuf files."""

    def __init__(self, dest: TextIO, meta: Dict[str, Any]):
        self.dest = dest
        self.logger = logging.getLogger("msggen.grpc.GrpcGenerator")
        self.meta = meta

    def write(self, text: str, cleanup: bool = True) -> None:
        if cleanup:
            self.dest.write(dedent(text))
        else:
            self.dest.write(text)

    def field2number(self, message_name: TypeName, field):
        m = self.meta["grpc-field-map"]

        message_name = (
            message_name.name
        )  # TypeName is not JSON-serializable, use the unaltered name.

        # Wrap each field mapping by the message_name, since otherwise
        # requests and responses share the same number space (just
        # cosmetic really, but why not do it?)
        if message_name not in m:
            m[message_name] = {}
        m = m[message_name]

        # Simple case first: if we've already assigned a number let's reuse that
        if field.path in m:
            return m[field.path]

        # Now let's find the highest number we have in the parent
        # context
        parent = ".".join(field.path.split(".")[:-1])
        maxnum = 0
        for k, v in m.items():
            parent2 = ".".join(k.split(".")[:-1])
            if parent2 == parent:
                maxnum = max(maxnum, v)

        m[field.path] = maxnum + 1
        self.logger.warn(
            f"Assigning new field number to {field.path} => {m[field.path]}"
        )

        return m[field.path]

    def enumerate_fields(self, message_name, fields):
        """Use the meta map to identify which number this field will get."""
        enumerated_values = [(self.field2number(message_name, f), f) for f in fields]
        sorted_enumerated_values = sorted(enumerated_values, key=lambda x: x[0])
        for i, v in sorted_enumerated_values:
            yield (i, v)

    def enumvar2number(self, typename: TypeName, variant):
        """Find an existing variant number of generate a new one.

        If we don't have a variant number yet we'll just take the
        largest one assigned so far and increment it by 1."""

        typename = str(typename.name)

        m = self.meta["grpc-enum-map"]
        variant = str(variant)
        if typename not in m:
            m[typename] = {}

        variants = m[typename]
        if variant in variants:
            return variants[variant]

        # Now find the maximum and increment once
        n = max(variants.values()) if len(variants) else -1

        m[typename][variant] = n + 1
        return m[typename][variant]

    def enumerate_enum(self, typename, variants):
        enumerated_values = [(self.enumvar2number(typename, v), v) for v in variants]
        sorted_enumerated_values = sorted(enumerated_values, key=lambda x: x[0])
        for i, v in sorted_enumerated_values:
            yield (i, v)

    def gather_types(self, service):
        """Gather all types that might need to be defined."""

        def gather_subfields(field: Field) -> List[Field]:
            fields = [field]

            if isinstance(field, CompositeField):
                for f in field.fields:
                    fields.extend(gather_subfields(f))
            elif isinstance(field, ArrayField):
                fields = []
                fields.extend(gather_subfields(field.itemtype))

            return fields

        types = []
        for method in service.methods:
            types.extend([method.request, method.response])
            for field in method.request.fields:
                types.extend(gather_subfields(field))
            for field in method.response.fields:
                types.extend(gather_subfields(field))

        for notification in service.notifications:
            types.extend([notification.request, notification.response])
            for field in notification.request.fields:
                types.extend(gather_subfields(field))
            for field in notification.response.fields:
                types.extend(gather_subfields(field))

        return types

    def generate_service(self, service: Service) -> None:
        self.write(
            f"""
        service {service.name} {{
        """
        )

        for method in service.methods:
            mname = MethodName(method_name_overrides.get(method.name, method.name))
            self.write(
                f"	rpc {mname}({method.request.typename}) returns ({method.response.typename}) {{}}\n",
                cleanup=False,
            )

        self.write(
            f"""}}
        """
        )

    def generate_enum(self, e: EnumField, indent=0):
        self.logger.debug(f"Generating enum {e}")
        prefix = "\t" * indent
        self.write(f"{prefix}// {e.path}\n", False)
        self.write(f"{prefix}enum {e.typename} {{\n", False)

        for i, v in self.enumerate_enum(e.typename, e.variants):
            self.logger.debug(f"Generating enum variant {v}")
            self.write(f"{prefix}\t{v.normalized()} = {i};\n", False)

        self.write(f"""{prefix}}}\n""", False)

    def generate_message(self, message: CompositeField):
        if message.omit():
            return

        self.write(
            f"""
        message {message.typename} {{
        """
        )

        # Declare enums inline so they are scoped correctly in C++
        for _, f in enumerate(message.fields):
            if isinstance(f, EnumField) and not f.override():
                self.generate_enum(f, indent=1)

        for i, f in self.enumerate_fields(message.typename, message.fields):
            if f.omit():
                continue

            opt = "optional " if f.optional else ""

            if isinstance(f, ArrayField):
                typename = f.override(
                    typemap.get(f.itemtype.typename, f.itemtype.typename)
                )
                self.write(f"\trepeated {typename} {f.normalized()} = {i};\n", False)
            elif isinstance(f, PrimitiveField):
                typename = f.override(typemap.get(f.typename, f.typename))
                self.write(f"\t{opt}{typename} {f.normalized()} = {i};\n", False)
            elif isinstance(f, EnumField):
                typename = f.override(f.typename)
                self.write(f"\t{opt}{typename} {f.normalized()} = {i};\n", False)
            elif isinstance(f, CompositeField):
                typename = f.override(f.typename)
                self.write(f"\t{opt}{typename} {f.normalized()} = {i};\n", False)

        self.write(
            """}
        """
        )

    def generate(self, service: Service) -> None:
        """Generate the GRPC protobuf file and write to `dest`"""
        self.write(f"""syntax = "proto3";\npackage cln;\n""")
        self.write(
            """
        // This file was automatically derived from the JSON-RPC schemas in
        // `doc/schemas`. Do not edit this file manually as it would get
        // overwritten.

        """
        )

        for i in service.includes:
            self.write(f'import "{i}";\n')

        self.generate_service(service)

        fields = self.gather_types(service)

        for message in [f for f in fields if isinstance(f, CompositeField)]:
            self.generate_message(message)
