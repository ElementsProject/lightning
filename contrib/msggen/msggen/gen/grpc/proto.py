# A grpc model
from typing import TextIO, List, Dict, Any
from textwrap import dedent
import logging
import re

from msggen.gen import IGenerator
from msggen.gen.grpc.util import (
    typemap,
    method_name_overrides,
    notification_typename_overrides,
)
from msggen.gen.grpc import wire
from msggen.model import (
    ArrayField,
    Field,
    FieldName,
    CompositeField,
    EnumField,
    EnumVariant,
    PrimitiveField,
    Service,
    MethodName,
    TypeName,
    Notification,
    Method,
)


class GrpcGenerator(IGenerator):
    """A generator that generates protobuf files."""

    def __init__(self, dest: TextIO, meta: Dict[str, Any], state: wire.WireState):
        self.dest = dest
        self.logger = logging.getLogger("msggen.grpc.GrpcGenerator")
        self.meta = meta
        self.state = state
        wire.ensure_meta(meta)

    def write(self, text: str, cleanup: bool = True) -> None:
        if cleanup:
            self.dest.write(dedent(text))
        else:
            self.dest.write(text)

    def field2number(self, message_name: TypeName, field, taken=()):
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
        maxnum = max(taken, default=0)
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

    @staticmethod
    def enum_typename_key(typename) -> str:
        """Canonical key for grpc-enum-map enum entries.

        enumvar2number() and enumerate_enum() must derive this key the
        same way.  TypeName.__str__() strips '-' and rewrites '/', so
        don't use it here: the map keys have always been the raw
        TypeName.name.
        """
        if isinstance(typename, TypeName):
            return str(typename.name)
        return str(typename)

    def enumvar2number(self, typename: TypeName, variant):
        """Find an existing variant number of generate a new one.

        If we don't have a variant number yet we'll just take the
        largest one assigned so far and increment it by 1."""

        typename = self.enum_typename_key(typename)

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
        """Yield (number, variant, deprecated) for each enum entry.

        Entries that were previously assigned a number in grpc-enum-map
        but are no longer in the schema are emitted as deprecated so
        their wire values are never reassigned and proto3's zero-value
        requirement is preserved.
        """
        variant_strs = {str(v) for v in variants}
        enumerated_values = [(self.enumvar2number(typename, v), v, False)
                             for v in variants]

        persisted = self.meta["grpc-enum-map"].get(
            self.enum_typename_key(typename), {})
        for name, number in persisted.items():
            if name not in variant_strs:
                enumerated_values.append((number, EnumVariant(name), True))

        sorted_enumerated_values = sorted(enumerated_values,
                                          key=lambda x: x[0])
        for i, v, removed in sorted_enumerated_values:
            yield (i, v, removed)

    def gather_method_types(self, methods: List[Method]):
        """Gather all types that might need to be defined."""
        types = []
        for method in methods:
            types.extend([method.request, method.response])
            for field in method.request.fields:
                types.extend(gather_subfields(field))
            for field in method.response.fields:
                types.extend(gather_subfields(field))

        return types

    def gather_notification_types(self, notifications: List[Notification]):
        """Gather all types that might need to be defined
        to represent notifications
        """
        types = []
        for notification in notifications:
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

        self.write("\n")
        for notification in service.notifications:
            name = str(notification.typename)
            response_type_name = notification_typename_overrides(
                notification.response.typename
            )
            self.write(
                f"	rpc Subscribe{name}({notification.request.typename}) returns (stream {response_type_name}) {{}}\n",
                cleanup=False,
            )

        self.write(
            f"""}}
        """
        )

    def generate_enum(self, e: EnumField, indent=0, typename_override=None):
        if typename_override is None:
            typename_override = lambda x: x

        self.logger.debug(f"Generating enum {e}")
        prefix = "\t" * indent
        self.write(f"{prefix}// {e.path}\n", False)
        self.write(f"{prefix}enum {typename_override(e.typename)} {{\n", False)

        for i, v, removed in self.enumerate_enum(typename_override(e.typename), e.variants):
            self.logger.debug(f"Generating enum variant {v}")
            if removed:
                self.write(f"{prefix}\t{v.normalized()} = {i} [deprecated = true];\n", False)
            else:
                depri = " [deprecated = true]" if e.deprecated else ""
                self.write(f"{prefix}\t{v.normalized()} = {i}{depri};\n", False)

        self.write(f"""{prefix}}}\n""", False)

    def generate_message(self, message: CompositeField, typename_override=None):
        if message.omit():
            return

        # If override is not specified it is a function that returns itself
        # This is equivalent to do not override
        if typename_override is None:
            typename_override = lambda x: x

        self.write(
            f"""
        message {typename_override(message.typename)} {{
        """
        )

        # Declare enums inline so they are scoped correctly in C++
        for _, f in enumerate(message.fields):
            if isinstance(f, EnumField) and not f.override():
                self.generate_enum(f, indent=1, typename_override=typename_override)

        pbname = str(typename_override(message.typename))
        contract = self.meta["grpc-wire-contract"].setdefault(pbname, {})
        emitted = []

        for i, f in self.enumerate_fields(message.typename, message.fields):
            if f.omit():
                continue

            label, typename = self.field_decl(f, typename_override)
            name = f.normalized()
            key = f"{pbname}.{f.path}"
            current = {"label": label, "type": self.wire_type(f, typename)}
            schema_type = getattr(f, "typename", None)

            if str(i) not in contract:
                contract[str(i)] = wire.pack(current)
            resolved = wire.resolve(
                f.path, schema_type, wire.unpack(contract[str(i)]), current
            )

            if resolved.get("renumber"):
                # Keep serving the released msat field under its old
                # number, and move the sat value to a new one.
                legacy = self.meta["grpc-legacy-fields"].setdefault(
                    f.path, {"number": i, **wire.unpack(contract[str(i)])}
                )
                self.state.legacy[key] = {"new_name": f"{name}_sat", **legacy}
                emitted.append(
                    (legacy["number"], legacy["label"], legacy["type"], name, True)
                )
                name = f"{name}_sat"
                i = self.field2number(
                    message.typename,
                    wire.RenumberedField(f.path),
                    taken=[int(n) for n in contract],
                )
                if str(i) not in contract:
                    contract[str(i)] = wire.pack(current)
                resolved = wire.resolve(
                    f.path, schema_type, wire.unpack(contract[str(i)]), current
                )
                if resolved.get("renumber"):
                    raise wire.WireCompatError(f"{f.path}: renumbered twice")

            contract[str(i)] = wire.pack(
                {
                    "label": resolved["label"],
                    "type": wire.unpack(contract[str(i)])["type"],
                }
            )

            if resolved["type"] != current["type"]:
                self.state.pinned[key] = {"proto": resolved, "schema": current}
                typename = resolved["type"]
            elif resolved["label"] != current["label"] and wire.is_scalar(current):
                # Message fields are `Option<T>` in prost regardless of
                # the label, so only scalars need converting.
                self.state.pinned[key] = {"proto": resolved, "schema": current}

            emitted.append((i, resolved["label"], typename, name, bool(f.deprecated)))

        used = {e[0] for e in emitted}
        known = {int(n) for n in contract}
        known |= set(
            self.meta["grpc-field-map"].get(message.typename.name, {}).values()
        )
        reserved = sorted(known - used)
        names = {
            num: path.split(".")[-1].replace("[]", "")
            for path, num in self.meta["grpc-field-map"]
            .get(message.typename.name, {})
            .items()
        }
        emitted_names = {e[3] for e in emitted}
        reserved_names = sorted(
            {
                FieldName(names[n]).normalized()
                for n in reserved
                if n in names and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", names[n])
            }
            - emitted_names
        )

        for i, label, typename, name, deprecated in sorted(emitted):
            depri = " [deprecated = true]" if deprecated else ""
            self.write(
                f"\t{self.decl_label(label)}{typename} {name} = {i}{depri};\n", False
            )

        if reserved:
            nums = ", ".join(str(n) for n in reserved)
            self.write(f"\treserved {nums};\n", False)
        if reserved_names:
            quoted = ", ".join(f'"{n}"' for n in reserved_names)
            self.write(f"\treserved {quoted};\n", False)

        self.write(
            """}
        """
        )

    @staticmethod
    def decl_label(label: str) -> str:
        return "" if label == "plain" else f"{label} "

    def field_decl(self, f: Field, typename_override):
        """Return the (label, typename) the schema implies for a field."""
        if isinstance(f, ArrayField):
            typename = f.override(typemap.get(f.itemtype.typename, f.itemtype.typename))
            return "repeated", typename

        if isinstance(f, PrimitiveField):
            typename = typename_override(
                f.override(typemap.get(f.typename, f.typename))
            )
            if f.typename == "string_map":
                return "plain", typename
        else:
            typename = typename_override(f.override(f.typename))
        return ("optional" if f.optional else "plain"), str(typename)

    @staticmethod
    def wire_type(f: Field, typename: str) -> str:
        """Generated types are only identified by kind, since their
        names derive from the (stable) field path."""
        item = f.itemtype if isinstance(f, ArrayField) else f
        if isinstance(item, CompositeField):
            return "message"
        if isinstance(item, EnumField):
            return "enum"
        return typename

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

        method_fields = self.gather_method_types(service.methods)
        notification_fields = self.gather_notification_types(service.notifications)

        for message in [f for f in method_fields if isinstance(f, CompositeField)]:
            self.generate_message(message)

        for message in [
            f for f in notification_fields if isinstance(f, CompositeField)
        ]:
            self.generate_message(message, notification_typename_overrides)


def gather_subfields(field: Field) -> List[Field]:
    fields = [field]

    if isinstance(field, CompositeField):
        for f in field.fields:
            fields.extend(gather_subfields(f))
    elif isinstance(field, ArrayField):
        fields = []
        fields.extend(gather_subfields(field.itemtype))

    return fields
