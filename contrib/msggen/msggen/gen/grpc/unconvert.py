# A grpc model
from msggen.model import ArrayField, CompositeField, EnumField, PrimitiveField, Service
from msggen.gen.grpc.convert import GrpcConverterGenerator


class GrpcUnconverterGenerator(GrpcConverterGenerator):
    """Generator to generate the conversions from GRPC to JSON-RPC (for requests)."""

    def generate(self, service: Service):
        self.generate_requests(service)

        # TODO Temporarily disabled since the use of overrides is lossy
        # self.generate_responses(service)

    def generate_composite(self, prefix, field: CompositeField, override=None) -> None:
        # First pass: generate any sub-fields before we generate the
        # top-level field itself.
        if field.omit():
            return

        if override is None:
            override = lambda x: x

        for f in field.fields:
            if isinstance(f, ArrayField):
                self.generate_array(prefix, f, override)
            elif isinstance(f, CompositeField):
                self.generate_composite(prefix, f, override)

        has_deprecated = any([f.deprecated for f in field.fields])
        deprecated = ",deprecated" if has_deprecated else ""

        pbname = self.to_camel_case(str(field.typename))
        # And now we can convert the current field:
        self.write(
            f"""\
        #[allow(unused_variables{deprecated})]
        impl From<pb::{pbname}> for {prefix}::{field.typename} {{
            fn from(c: pb::{pbname}) -> Self {{
                Self {{
        """
        )

        for f in field.fields:
            name = f.normalized()
            if f.omit():
                continue

            if isinstance(f, ArrayField):
                typ = f.itemtype.typename
                mapping = {
                    "hex": f"hex::encode(s)",
                    "u32": f"s",
                    "secret": f"s.try_into().unwrap()",
                    "hash": f"Sha256::from_slice(&s).unwrap()",
                }.get(typ, f"s.into()")

                # TODO fix properly
                if typ in ["ListtransactionsTransactionsType"]:
                    continue
                if name == "state_changes":
                    self.write(f" state_changes: None,")
                    continue

                if not f.optional:
                    self.write(
                        f"{name}: c.{name}.into_iter().map(|s| {mapping}).collect(), // Rule #4\n",
                        numindent=3,
                    )
                else:
                    self.write(
                        f"{name}: Some(c.{name}.into_iter().map(|s| {mapping}).collect()), // Rule #4\n",
                        numindent=3,
                    )

            elif isinstance(f, EnumField):
                if f.path == "ListPeers.peers[].channels[].htlcs[].state":
                    continue
                if not f.optional:
                    self.write(f"{name}: c.{name}.try_into().unwrap(),\n", numindent=3)
                else:
                    self.write(
                        f"{name}: c.{name}.map(|v| v.try_into().unwrap()),\n",
                        numindent=3,
                    )
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
                    "u8": f"c.{name} as u8",
                    "u16": f"c.{name} as u16",
                    "u16?": f"c.{name}.map(|v| v as u16)",
                    "hex": f"hex::encode(&c.{name})",
                    "hex?": f"c.{name}.map(|v| hex::encode(v))",
                    "txid?": f"c.{name}.map(|v| hex::encode(v))",
                    "pubkey": f"PublicKey::from_slice(&c.{name}).unwrap()",
                    "pubkey?": f"c.{name}.map(|v| PublicKey::from_slice(&v).unwrap())",
                    "msat": f"c.{name}.unwrap().into()",
                    "msat?": f"c.{name}.map(|a| a.into())",
                    "msat_or_all": f"c.{name}.unwrap().into()",
                    "msat_or_all?": f"c.{name}.map(|a| a.into())",
                    "msat_or_any": f"c.{name}.unwrap().into()",
                    "msat_or_any?": f"c.{name}.map(|a| a.into())",
                    "feerate": f"c.{name}.unwrap().into()",
                    "feerate?": f"c.{name}.map(|a| a.into())",
                    "outpoint?": f"c.{name}.map(|a| a.into())",
                    "RoutehintList?": f"c.{name}.map(|rl| rl.into())",
                    "DecodeRoutehintList?": f"c.{name}.map(|drl| drl.into())",
                    "short_channel_id": f"cln_rpc::primitives::ShortChannelId::from_str(&c.{name}).unwrap()",
                    "short_channel_id?": f"c.{name}.map(|v| cln_rpc::primitives::ShortChannelId::from_str(&v).unwrap())",
                    "secret": f"c.{name}.try_into().unwrap()",
                    "secret?": f"c.{name}.map(|v| v.try_into().unwrap())",
                    "hash": f"Sha256::from_slice(&c.{name}).unwrap()",
                    "hash?": f"c.{name}.map(|v| Sha256::from_slice(&v).unwrap())",
                    "txid": f"hex::encode(&c.{name})",
                    "TlvStream?": f"c.{name}.map(|s| s.into())",
                }.get(
                    typ, f"c.{name}"  # default to just assignment
                )
                self.write(f"{name}: {rhs}, // Rule #1 for type {typ}\n", numindent=3)
            elif isinstance(f, CompositeField):
                rhs = ""
                if not f.optional:
                    rhs = f"c.{name}.unwrap().into()"
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
