# A grpc model
from msggen.model import ArrayField, Field, CompositeField, EnumField, PrimitiveField, Service, MethodName, TypeName
from msggen.gen import IGenerator
from typing import TextIO, List, Dict, Any
from textwrap import indent, dedent
import re
import logging


typemap = {
    'boolean': 'bool',
    'hex': 'bytes',
    'msat': 'Amount',
    'msat_or_all': 'AmountOrAll',
    'msat_or_any': 'AmountOrAny',
    'currency': 'string',
    'number': 'double',
    'pubkey': 'bytes',
    'short_channel_id': 'string',
    'signature': 'string',
    'string': 'string',
    'txid': 'bytes',
    'u8': 'uint32',  # Yep, this is the smallest integer type in grpc...
    'u32': 'uint32',
    'u64': 'uint64',
    's8': 'int32',
    's16': 'int32',
    's32': 'int32',
    's64': 'int64',
    'u16': 'uint32',  # Yeah, I know...
    'f32': 'float',
    'integer': 'sint64',
    "outpoint": "Outpoint",
    "feerate": "Feerate",
    "outputdesc": "OutputDesc",
    "secret": "bytes",
    "bip340sig": "string",
    "hash": "bytes",
}


# GRPC builds a stub with the methods declared in the protobuf file,
# but it also comes with its own methods, e.g., `connect` which can
# clash with the generated ones. So rename the ones we know clash.
method_name_overrides = {
    "Connect": "ConnectPeer",
}


class GrpcGenerator(IGenerator):
    """A generator that generates protobuf files.
    """

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
        m = self.meta['grpc-field-map']

        message_name = message_name.name  # TypeName is not JSON-serializable, use the unaltered name.

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
        parent = '.'.join(field.path.split('.')[:-1])
        maxnum = 0
        for k, v in m.items():
            parent2 = '.'.join(k.split('.')[:-1])
            if parent2 == parent:
                maxnum = max(maxnum, v)

        m[field.path] = maxnum + 1
        self.logger.warn(f"Assigning new field number to {field.path} => {m[field.path]}")

        return m[field.path]

    def enumerate_fields(self, message_name, fields):
        """Use the meta map to identify which number this field will get.
        """
        enumerated_values = [(self.field2number(message_name, f), f) for f in fields]
        sorted_enumerated_values = sorted(enumerated_values, key=lambda x: x[0])
        for i, v in sorted_enumerated_values:
            yield (i, v)

    def enumvar2number(self, typename: TypeName, variant):
        """Find an existing variant number of generate a new one.

        If we don't have a variant number yet we'll just take the
        largest one assigned so far and increment it by 1.  """

        typename = str(typename.name)

        m = self.meta['grpc-enum-map']
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
        """Gather all types that might need to be defined.
        """

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
        return types

    def generate_service(self, service: Service) -> None:
        self.write(f"""
        service {service.name} {{
        """)

        for method in service.methods:
            mname = MethodName(method_name_overrides.get(method.name, method.name))
            self.write(
                f"	rpc {mname}({method.request.typename}) returns ({method.response.typename}) {{}}\n",
                cleanup=False,
            )

        self.write(f"""}}
        """)

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

        self.write(f"""
        message {message.typename} {{
        """)

        # Declare enums inline so they are scoped correctly in C++
        for _, f in enumerate(message.fields):
            if isinstance(f, EnumField) and not f.override():
                self.generate_enum(f, indent=1)

        for i, f in self.enumerate_fields(message.typename, message.fields):
            if f.omit():
                continue

            opt = "optional " if f.optional else ""

            if isinstance(f, ArrayField):
                typename = f.override(typemap.get(f.itemtype.typename, f.itemtype.typename))
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

        self.write("""}
        """)

    def generate(self, service: Service) -> None:
        """Generate the GRPC protobuf file and write to `dest`
        """
        self.write(f"""syntax = "proto3";\npackage cln;\n""")
        self.write("""
        // This file was automatically derived from the JSON-RPC schemas in
        // `doc/schemas`. Do not edit this file manually as it would get
        // overwritten.

        """)

        for i in service.includes:
            self.write(f"import \"{i}\";\n")

        self.generate_service(service)

        fields = self.gather_types(service)

        for message in [f for f in fields if isinstance(f, CompositeField)]:
            self.generate_message(message)


class GrpcConverterGenerator(IGenerator):
    def __init__(self, dest: TextIO):
        self.dest = dest
        self.logger = logging.getLogger("msggen.grpc.GrpcConversionGenerator")

    def generate_array(self, prefix, field: ArrayField):
        if isinstance(field.itemtype, CompositeField):
            self.generate_composite(prefix, field.itemtype)

    def generate_composite(self, prefix, field: CompositeField):
        """Generates the conversions from JSON-RPC to GRPC.
        """
        if field.omit():
            return

        field.sort()

        # First pass: generate any sub-fields before we generate the
        # top-level field itself.
        for f in field.fields:
            if isinstance(f, ArrayField):
                self.generate_array(prefix, f)
            elif isinstance(f, CompositeField):
                self.generate_composite(prefix, f)

        pbname = self.to_camel_case(str(field.typename))

        # If any of the field accesses would result in a deprecated
        # warning we mark the construction here to allow deprecated
        # fields being access.

        has_deprecated = any([f.deprecated for f in field.fields])
        deprecated = ",deprecated" if has_deprecated else ""

        # And now we can convert the current field:
        self.write(f"""\
        #[allow(unused_variables{deprecated})]
        impl From<{prefix}::{field.typename}> for pb::{pbname} {{
            fn from(c: {prefix}::{field.typename}) -> Self {{
                Self {{
        """)

        for f in field.fields:
            if f.omit():
                continue

            name = f.normalized()
            name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
            if isinstance(f, ArrayField):
                typ = f.itemtype.typename
                # The inner conversion applied to each element in the
                # array. The current item is called `i`
                mapping = {
                    'hex': f'hex::decode(i).unwrap()',
                    'secret': f'i.to_vec()',
                    'hash': f'<Sha256 as AsRef<[u8]>>::as_ref(&i).to_vec()',
                }.get(typ, f'i.into()')

                self.write(f"// Field: {f.path}\n", numindent=3)
                if not f.optional:
                    self.write(f"{name}: c.{name}.into_iter().map(|i| {mapping}).collect(), // Rule #3 for type {typ}\n", numindent=3)
                else:
                    self.write(f"{name}: c.{name}.map(|arr| arr.into_iter().map(|i| {mapping}).collect()).unwrap_or(vec![]), // Rule #3\n", numindent=3)
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
                    'u8': f'c.{name}.into()',
                    'u16': f'c.{name}.into()',
                    'u16?': f'c.{name}.map(|v| v.into())',
                    'msat': f'Some(c.{name}.into())',
                    'msat?': f'c.{name}.map(|f| f.into())',
                    'pubkey': f'c.{name}.serialize().to_vec()',
                    'pubkey?': f'c.{name}.map(|v| v.serialize().to_vec())',
                    'hex': f'hex::decode(&c.{name}).unwrap()',
                    'hex?': f'c.{name}.map(|v| hex::decode(v).unwrap())',
                    'txid': f'hex::decode(&c.{name}).unwrap()',
                    'txid?': f'c.{name}.map(|v| hex::decode(v).unwrap())',
                    'short_channel_id': f'c.{name}.to_string()',
                    'short_channel_id?': f'c.{name}.map(|v| v.to_string())',
                    'hash': f'<Sha256 as AsRef<[u8]>>::as_ref(&c.{name}).to_vec()',
                    'hash?': f'c.{name}.map(|v| <Sha256 as AsRef<[u8]>>::as_ref(&v).to_vec())',
                    'secret': f'c.{name}.to_vec()',
                    'secret?': f'c.{name}.map(|v| v.to_vec())',
                    'msat_or_any': f'Some(c.{name}.into())',
                    'msat_or_all': f'Some(c.{name}.into())',
                    'msat_or_all?': f'c.{name}.map(|o|o.into())',
                    'feerate?': f'c.{name}.map(|o|o.into())',
                    'feerate': f'Some(c.{name}.into())',
                    'outpoint?': f'c.{name}.map(|o|o.into())',
                    'TlvStream?': f'c.{name}.map(|s| s.into())',
                    'RoutehintList?': f'c.{name}.map(|rl| rl.into())',


                }.get(
                    typ,
                    f'c.{name}'  # default to just assignment
                )

                if f.deprecated:
                    self.write(f"#[allow(deprecated)]\n", numindent=3)
                self.write(f"{name}: {rhs}, // Rule #2 for type {typ}\n", numindent=3)

            elif isinstance(f, CompositeField):
                rhs = ""
                if not f.optional:
                    rhs = f'Some(c.{name}.into())'
                else:
                    rhs = f'c.{name}.map(|v| v.into())'
                self.write(f"{name}: {rhs},\n", numindent=3)
        self.write(f"""\
                }}
            }}
        }}

        """)

    def to_camel_case(self, snake_str):
        components = snake_str.split('_')
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

    def generate_requests(self, service):
        for meth in service.methods:
            req = meth.request
            self.generate_composite("requests", req)

    def generate_responses(self, service):
        for meth in service.methods:
            res = meth.response
            self.generate_composite("responses", res)

    def generate(self, service: Service) -> None:
        self.write("""
        // This file was automatically derived from the JSON-RPC schemas in
        // `doc/schemas`. Do not edit this file manually as it would get
        // overwritten.

        use std::convert::From;
        #[allow(unused_imports)]
        use cln_rpc::model::{responses,requests};
        use crate::pb;
        use std::str::FromStr;
        use bitcoin::hashes::sha256::Hash as Sha256;
        use bitcoin::hashes::Hash;
        use cln_rpc::primitives::PublicKey;

        """)

        self.generate_responses(service)
        self.generate_requests(service)
        self.write("\n")

    def write(self, text: str, numindent: int = 0) -> None:
        raw = dedent(text)
        if numindent > 0:
            raw = indent(text, "    " * numindent)

        self.dest.write(raw)


class GrpcUnconverterGenerator(GrpcConverterGenerator):
    """Generator to generate the conversions from GRPC to JSON-RPC (for requests).
    """
    def generate(self, service: Service):
        self.generate_requests(service)

        # TODO Temporarily disabled since the use of overrides is lossy
        # self.generate_responses(service)

    def generate_composite(self, prefix, field: CompositeField) -> None:
        # First pass: generate any sub-fields before we generate the
        # top-level field itself.
        if field.omit():
            return

        for f in field.fields:
            if isinstance(f, ArrayField):
                self.generate_array(prefix, f)
            elif isinstance(f, CompositeField):
                self.generate_composite(prefix, f)

        has_deprecated = any([f.deprecated for f in field.fields])
        deprecated = ",deprecated" if has_deprecated else ""

        pbname = self.to_camel_case(str(field.typename))
        # And now we can convert the current field:
        self.write(f"""\
        #[allow(unused_variables{deprecated})]
        impl From<pb::{pbname}> for {prefix}::{field.typename} {{
            fn from(c: pb::{pbname}) -> Self {{
                Self {{
        """)

        for f in field.fields:
            name = f.normalized()
            if f.omit():
                continue

            if isinstance(f, ArrayField):
                typ = f.itemtype.typename
                mapping = {
                    'hex': f'hex::encode(s)',
                    'u32': f's',
                    'secret': f's.try_into().unwrap()',
                    'hash': f'Sha256::from_slice(&s).unwrap()',
                }.get(typ, f's.into()')

                # TODO fix properly
                if typ in ["ListtransactionsTransactionsType"]:
                    continue
                if name == 'state_changes':
                    self.write(f" state_changes: None,")
                    continue

                if not f.optional:
                    self.write(f"{name}: c.{name}.into_iter().map(|s| {mapping}).collect(), // Rule #4\n", numindent=3)
                else:
                    self.write(f"{name}: Some(c.{name}.into_iter().map(|s| {mapping}).collect()), // Rule #4\n", numindent=3)

            elif isinstance(f, EnumField):
                if f.path == 'ListPeers.peers[].channels[].htlcs[].state':
                    continue
                if not f.optional:
                    self.write(f"{name}: c.{name}.try_into().unwrap(),\n", numindent=3)
                else:
                    self.write(f"{name}: c.{name}.map(|v| v.try_into().unwrap()),\n", numindent=3)
                pass
            elif isinstance(f, PrimitiveField):
                typ = f.typename + ("?" if f.optional else "")
                # We may need to reduce or increase the size of some
                # types, or have some conversion such as
                # hex-decoding. Also includes the `Some()` that grpc
                # requires for non-native types.

                if name == "scriptPubKey":
                    name = "script_pub_key"

                rhs = {
                    'u8': f'c.{name} as u8',
                    'u16': f'c.{name} as u16',
                    'u16?': f'c.{name}.map(|v| v as u16)',
                    'hex': f'hex::encode(&c.{name})',
                    'hex?': f'c.{name}.map(|v| hex::encode(v))',
                    'txid?': f'c.{name}.map(|v| hex::encode(v))',
                    'pubkey': f'PublicKey::from_slice(&c.{name}).unwrap()',
                    'pubkey?': f'c.{name}.map(|v| PublicKey::from_slice(&v).unwrap())',
                    'msat': f'c.{name}.unwrap().into()',
                    'msat?': f'c.{name}.map(|a| a.into())',
                    'msat_or_all': f'c.{name}.unwrap().into()',
                    'msat_or_all?': f'c.{name}.map(|a| a.into())',
                    'msat_or_any': f'c.{name}.unwrap().into()',
                    'msat_or_any?': f'c.{name}.map(|a| a.into())',
                    'feerate': f'c.{name}.unwrap().into()',
                    'feerate?': f'c.{name}.map(|a| a.into())',
                    'outpoint?': f'c.{name}.map(|a| a.into())',
                    'RoutehintList?': f'c.{name}.map(|rl| rl.into())',
                    'short_channel_id': f'cln_rpc::primitives::ShortChannelId::from_str(&c.{name}).unwrap()',
                    'short_channel_id?': f'c.{name}.map(|v| cln_rpc::primitives::ShortChannelId::from_str(&v).unwrap())',
                    'secret': f'c.{name}.try_into().unwrap()',
                    'secret?': f'c.{name}.map(|v| v.try_into().unwrap())',
                    'hash': f'Sha256::from_slice(&c.{name}).unwrap()',
                    'hash?': f'c.{name}.map(|v| Sha256::from_slice(&v).unwrap())',
                    'txid': f'hex::encode(&c.{name})',
                    'TlvStream?': f'c.{name}.map(|s| s.into())',
                }.get(
                    typ,
                    f'c.{name}'  # default to just assignment
                )
                self.write(f"{name}: {rhs}, // Rule #1 for type {typ}\n", numindent=3)
            elif isinstance(f, CompositeField):
                rhs = ""
                if not f.optional:
                    rhs = f'c.{name}.unwrap().into()'
                else:
                    rhs = f'c.{name}.map(|v| v.into())'
                self.write(f"{name}: {rhs},\n", numindent=3)

        self.write(f"""\
                }}
            }}
        }}

        """)


class GrpcServerGenerator(GrpcConverterGenerator):
    def generate(self, service: Service) -> None:
        self.write(f"""\
        use crate::pb::node_server::Node;
        use crate::pb;
        use cln_rpc::{{Request, Response, ClnRpc}};
        use anyhow::Result;
        use std::path::{{Path, PathBuf}};
        use cln_rpc::model::requests;
        use log::{{debug, trace}};
        use tonic::{{Code, Status}};

        #[derive(Clone)]
        pub struct Server
        {{
            rpc_path: PathBuf,
        }}

        impl Server
        {{
            pub async fn new(path: &Path) -> Result<Self>
            {{
                Ok(Self {{
                    rpc_path: path.to_path_buf(),
                }})
            }}
        }}

        #[tonic::async_trait]
        impl Node for Server
        {{
        """)

        for method in service.methods:
            mname = method_name_overrides.get(method.name, method.name)
            # Tonic will convert to snake-case, so we have to do it here too
            name = re.sub(r'(?<!_)(?<!^)(?=[A-Z])', '_', mname).lower()
            name = name.replace("-", "")
            method.name = method.name.replace("-", "")
            pbname_request = self.to_camel_case(str(method.request.typename))
            pbname_response = self.to_camel_case(str(method.response.typename))
            self.write(f"""\
            async fn {name}(
                &self,
                request: tonic::Request<pb::{pbname_request}>,
            ) -> Result<tonic::Response<pb::{pbname_response}>, tonic::Status> {{
                let req = request.into_inner();
                let req: requests::{method.request.typename} = req.into();
                debug!("Client asked for {name}");
                trace!("{name} request: {{:?}}", req);
                let mut rpc = ClnRpc::new(&self.rpc_path)
                    .await
                    .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
                let result = rpc.call(Request::{method.name}(req))
                    .await
                    .map_err(|e| Status::new(
                       Code::Unknown,
                       format!("Error calling method {method.name}: {{:?}}", e)))?;
                match result {{
                    Response::{method.name}(r) => {{
                       trace!("{name} response: {{:?}}", r);
                       Ok(tonic::Response::new(r.into()))
                    }},
                    r => Err(Status::new(
                        Code::Internal,
                        format!(
                            "Unexpected result {{:?}} to method call {method.name}",
                            r
                        )
                    )),
                }}

            }}\n\n""", numindent=0)

        self.write(f"""\
        }}
        """, numindent=0)
