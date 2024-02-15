# A grpc model
from msggen.model import ArrayField, CompositeField, EnumField, PrimitiveField, Service
from msggen.gen.grpc.util import notification_typename_overrides
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
                    "pubkey": f"c.{name}.serialize().to_vec()",
                    "pubkey?": f"c.{name}.map(|v| v.serialize().to_vec())",
                    "hex": f"hex::decode(&c.{name}).unwrap()",
                    "hex?": f"c.{name}.map(|v| hex::decode(v).unwrap())",
                    "txid": f"hex::decode(&c.{name}).unwrap()",
                    "txid?": f"c.{name}.map(|v| hex::decode(v).unwrap())",
                    "short_channel_id": f"c.{name}.to_string()",
                    "short_channel_id?": f"c.{name}.map(|v| v.to_string())",
                    "hash": f"<Sha256 as AsRef<[u8]>>::as_ref(&c.{name}).to_vec()",
                    "hash?": f"c.{name}.map(|v| <Sha256 as AsRef<[u8]>>::as_ref(&v).to_vec())",
                    "secret": f"c.{name}.to_vec()",
                    "secret?": f"c.{name}.map(|v| v.to_vec())",
                    "msat_or_any": f"Some(c.{name}.into())",
                    "msat_or_all": f"Some(c.{name}.into())",
                    "msat_or_all?": f"c.{name}.map(|o|o.into())",
                    "feerate?": f"c.{name}.map(|o|o.into())",
                    "feerate": f"Some(c.{name}.into())",
                    "outpoint?": f"c.{name}.map(|o|o.into())",
                    "TlvStream?": f"c.{name}.map(|s| s.into())",
                    "RoutehintList?": f"c.{name}.map(|rl| rl.into())",
                }.get(
                    typ, f"c.{name}"  # default to just assignment
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
