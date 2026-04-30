# A grpc model
from msggen.model import ArrayField, CompositeField, EnumField, PrimitiveField, UnionField, Service
from msggen.gen.grpc.util import notification_typename_overrides, camel_to_snake, union_variant_suffix
from msggen.gen.rpc.rust import union_variant_name
from msggen.gen import IGenerator
from typing import TextIO
from textwrap import indent, dedent
import re
import logging


class GrpcConverterGenerator(IGenerator):
    def __init__(self, dest: TextIO):
        self.dest = dest
        self.logger = logging.getLogger("msggen.grpc.GrpcConversionGenerator")

    def generate_array(self, prefix, field: ArrayField, override):
        if isinstance(field.itemtype, CompositeField):
            self.generate_composite(prefix, field.itemtype, override)

    def union_variant_conversion(self, f, val="v"):
        """Generate the conversion expression for a single union variant value."""
        if isinstance(f, PrimitiveField):
            mapping = {
                "short_channel_id": f"{val}.to_string()",
                "short_channel_id_dir": f"{val}.to_string()",
                "pubkey": f"{val}.serialize().to_vec()",
                "hex": f"hex::decode({val}).unwrap()",
                "txid": f"hex::decode({val}).unwrap()",
                "hash": f"<Sha256 as AsRef<[u8]>>::as_ref(&{val}).to_vec()",
                "secret": f"{val}.to_vec()",
                "msat": f"{val}.into()",
                "msat_or_all": f"{val}.into()",
                "msat_or_any": f"{val}.into()",
                "sat": f"{val}.into()",
                "sat_or_all": f"{val}.into()",
                "feerate": f"{val}.into()",
                "outpoint": f"{val}.into()",
            }.get(f.typename, val)
            return mapping
        elif isinstance(f, ArrayField):
            inner_mapping = {
                "short_channel_id": "i.to_string()",
                "short_channel_id_dir": "i.to_string()",
                "pubkey": "i.serialize().to_vec()",
                "hex": "hex::decode(i).unwrap()",
                "txid": "hex::decode(i).unwrap()",
            }.get(f.itemtype.typename, "i.into()")
            return f"{val}.into_iter().map(|i| {inner_mapping}).collect()"
        elif isinstance(f, EnumField):
            return f"{val} as i32"
        elif isinstance(f, CompositeField):
            return f"{val}.into()"
        return val

    def generate_union(self, prefix, field: UnionField, parent_typename, override=None):
        """Generate From impl for a union type (cln-rpc enum -> pb oneof)."""
        if override is None:
            override = lambda x: x

        typename = str(field.typename)
        pbname = override(self.to_camel_case(str(override(parent_typename))))
        pb_mod = camel_to_snake(pbname)
        oneof_name = field.normalized()
        # The prost enum name is CamelCase of the oneof field name
        pb_oneof_enum = self.to_camel_case(oneof_name[0].upper() + oneof_name[1:])

        self.write(
            f"""\
        impl From<{prefix}::{typename}> for pb::{pb_mod}::{pb_oneof_enum} {{
            fn from(c: {prefix}::{typename}) -> Self {{
                match c {{
        """
        )

        for v in field.variants:
            vname = union_variant_name(v)
            suffix = union_variant_suffix(v)
            pb_variant = self.to_camel_case(f"{oneof_name}_{suffix}")
            pb_variant = pb_variant[0].upper() + pb_variant[1:]
            if isinstance(v, ArrayField):
                wrapper_name = override(f"{parent_typename}{suffix}Wrapper")
                wrapper_pb = self.to_camel_case(str(wrapper_name))
                self.write(
                    f"            {prefix}::{typename}::{vname}(v) => pb::{pb_mod}::{pb_oneof_enum}::{pb_variant}(pb::{wrapper_pb} {{ items: v.into_iter().map(|i| {self.union_variant_conversion(v.itemtype, 'i')}).collect() }}),\n"
                )
            else:
                self.write(
                    f"            {prefix}::{typename}::{vname}(v) => pb::{pb_mod}::{pb_oneof_enum}::{pb_variant}({self.union_variant_conversion(v)}),\n"
                )

        self.write(
            f"""\
                }}
            }}
        }}

        """
        )

    def generate_composite(self, prefix, field: CompositeField, override=None):
        """Generates the conversions from JSON-RPC to GRPC."""
        if field.omit():
            return

        if override is None:
            override = lambda x: x

        field.sort()

        # First pass: generate any sub-fields before we generate the
        # top-level field itself.
        for f in field.fields:
            if isinstance(f, ArrayField):
                self.generate_array(prefix, f, override)
            elif isinstance(f, CompositeField):
                self.generate_composite(prefix, f, override)
            elif isinstance(f, UnionField):
                self.generate_union(prefix, f, str(field.typename), override)

        pbname = override(self.to_camel_case(str(override(field.typename))))

        # If any of the field accesses would result in a deprecated
        # warning we mark the construction here to allow deprecated
        # fields being access.

        has_deprecated = any([f.deprecated for f in field.fields])
        deprecated = ",deprecated" if has_deprecated else ""

        # And now we can convert the current field:
        self.write(
            f"""\
        #[allow(unused_variables{deprecated})]
        impl From<{prefix}::{field.typename}> for pb::{pbname} {{
            fn from(c: {prefix}::{field.typename}) -> Self {{
                Self {{
        """
        )

        for f in field.fields:
            if f.omit():
                continue

            name = f.normalized()
            name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
            if isinstance(f, ArrayField):
                typ = f.itemtype.typename
                # The inner conversion applied to each element in the
                # array. The current item is called `i`
                mapping = {
                    "hex": f"hex::decode(i).unwrap()",
                    "secret": f"i.to_vec()",
                    "hash": f"<Sha256 as AsRef<[u8]>>::as_ref(&i).to_vec()",
                    "short_channel_id": f"i.to_string()",
                    "short_channel_id_dir": f"i.to_string()",
                    "pubkey": f"i.serialize().to_vec()",
                    "txid": f"hex::decode(i).unwrap()",
                }.get(typ, f"i.into()")

                self.write(f"// Field: {f.path}\n", numindent=3)
                if not f.optional:
                    self.write(
                        f"{name}: c.{name}.into_iter().map(|i| {mapping}).collect(), // Rule #3 for type {typ}\n",
                        numindent=3,
                    )
                else:
                    self.write(
                        f"{name}: c.{name}.map(|arr| arr.into_iter().map(|i| {mapping}).collect()).unwrap_or(vec![]), // Rule #3\n",
                        numindent=3,
                    )
            elif isinstance(f, EnumField):
                if not f.optional:
                    self.write(f"{name}: c.{name} as i32,\n", numindent=3)
                else:
                    self.write(f"{name}: c.{name}.map(|v| v as i32),\n", numindent=3)

            elif isinstance(f, PrimitiveField):
                typ = f.typename + ("?" if f.optional else "")
                # We may need to reduce or increase the size of some
                # types, or have some conversion such as
                # hex-decoding. Also includes the `Some()` that grpc
                # requires for non-native types.
                rhs = {
                    "u8": f"c.{name}.into()",
                    "u16": f"c.{name}.into()",
                    "u16?": f"c.{name}.map(|v| v.into())",
                    "msat": f"Some(c.{name}.into())",
                    "msat?": f"c.{name}.map(|f| f.into())",
                    "sat": f"Some(c.{name}.into())",
                    "sat?": f"c.{name}.map(|f| f.into())",
                    "pubkey": f"c.{name}.serialize().to_vec()",
                    "pubkey?": f"c.{name}.map(|v| v.serialize().to_vec())",
                    "hex": f"hex::decode(&c.{name}).unwrap()",
                    "hex?": f"c.{name}.map(|v| hex::decode(v).unwrap())",
                    "txid": f"hex::decode(&c.{name}).unwrap()",
                    "txid?": f"c.{name}.map(|v| hex::decode(v).unwrap())",
                    "short_channel_id": f"c.{name}.to_string()",
                    "short_channel_id?": f"c.{name}.map(|v| v.to_string())",
                    "short_channel_id_dir": f"c.{name}.to_string()",
                    "short_channel_id_dir?": f"c.{name}.map(|v| v.to_string())",
                    "hash": f"<Sha256 as AsRef<[u8]>>::as_ref(&c.{name}).to_vec()",
                    "hash?": f"c.{name}.map(|v| <Sha256 as AsRef<[u8]>>::as_ref(&v).to_vec())",
                    "secret": f"c.{name}.to_vec()",
                    "secret?": f"c.{name}.map(|v| v.to_vec())",
                    "msat_or_any": f"Some(c.{name}.into())",
                    "msat_or_all": f"Some(c.{name}.into())",
                    "msat_or_all?": f"c.{name}.map(|o|o.into())",
                    "sat_or_all": f"Some(c.{name}.into())",
                    "sat_or_all?": f"c.{name}.map(|o|o.into())",
                    "feerate?": f"c.{name}.map(|o|o.into())",
                    "feerate": f"Some(c.{name}.into())",
                    "outpoint?": f"c.{name}.map(|o|o.into())",
                    "outpoint": f"Some(c.{name}.into())",
                    "TlvStream?": f"c.{name}.map(|s| s.into())",
                    "RoutehintList?": f"c.{name}.map(|rl| rl.into())",
                    "DecodeRoutehintList?": f"c.{name}.map(|drl| drl.into())",
                    "string_map": f"Some(c.{name})",
                    "string_map?": f"c.{name}.unwrap_or(HashMap::new())",
                    "json_object_or_array": f"Some(c.{name})",
                    "json_object_or_array?": f"c.{name}.map(|f| f.into())",
                    "json_scalar": f"Some(c.{name})",
                    "json_scalar?": f"c.{name}.map(|f| f.into())",
                }.get(
                    typ,
                    f"c.{name}",  # default to just assignment
                )

                if f.deprecated:
                    self.write(f"#[allow(deprecated)]\n", numindent=3)
                self.write(f"{name}: {rhs}, // Rule #2 for type {typ}\n", numindent=3)

            elif isinstance(f, CompositeField):
                rhs = ""
                if not f.optional:
                    rhs = f"Some(c.{name}.into())"
                else:
                    rhs = f"c.{name}.map(|v| v.into())"
                self.write(f"{name}: {rhs},\n", numindent=3)

            elif isinstance(f, UnionField):
                if not f.optional:
                    self.write(f"{name}: Some(c.{name}.into()),\n", numindent=3)
                else:
                    self.write(f"{name}: c.{name}.map(|v| v.into()),\n", numindent=3)

        self.write(
            f"""\
                }}
            }}
        }}

        """
        )

    def to_camel_case(self, snake_str):
        components = snake_str.split("_")
        # We capitalize the first letter of each component except the first one
        # with the 'capitalize' method and join them together, while preserving
        # existing camel cases.
        camel_case = components[0]
        for word in components[1:]:
            if not word.isupper():
                camel_case += word[0].upper() + word[1:]
            else:
                camel_case += word.capitalize()
        return camel_case

    def generate_requests(self, service: Service):
        for meth in service.methods:
            req = meth.request
            self.generate_composite("requests", req)

        for notification in service.notifications:
            req = notification.request
            self.generate_composite(
                "notifications::requests", req, notification_typename_overrides
            )

    def generate_responses(self, service: Service):
        for meth in service.methods:
            res = meth.response
            self.generate_composite("responses", res)

        for notification in service.notifications:
            res = notification.response
            self.generate_composite(
                "notifications", res, notification_typename_overrides
            )

    def generate(self, service: Service) -> None:
        self.write(
            """
        // This file was automatically derived from the JSON-RPC schemas in
        // `doc/schemas`. Do not edit this file manually as it would get
        // overwritten.

        use std::convert::From;
        #[allow(unused_imports)]
        use cln_rpc::model::{responses,requests};
        use cln_rpc::notifications;
        use crate::pb;
        use std::str::FromStr;
        use std::collections::HashMap;
        use bitcoin::hashes::sha256::Hash as Sha256;
        use bitcoin::hashes::Hash;
        use cln_rpc::primitives::PublicKey;

        """
        )

        self.generate_responses(service)
        self.generate_requests(service)
        self.write("\n")

    def write(self, text: str, numindent: int = 0) -> None:
        raw = dedent(text)
        if numindent > 0:
            raw = indent(text, "    " * numindent)

        self.dest.write(raw)
