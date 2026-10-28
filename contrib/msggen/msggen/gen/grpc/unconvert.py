# A grpc model
from msggen.model import ArrayField, CompositeField, EnumField, PrimitiveField, Service
from msggen.gen.grpc.convert import GrpcConverterGenerator


class GrpcUnconverterGenerator(GrpcConverterGenerator):
    """Generator to generate the conversions from GRPC to JSON-RPC (for requests)."""

    def generate(self, service: Service):
        self.write_helpers()
        self.generate_requests(service)

        # TODO Temporarily disabled since the use of overrides is lossy
        # self.generate_responses(service)

    def write_helpers(self) -> None:
        self.write(
            """
        fn invalid_argument(field: &str, err: impl std::fmt::Display) -> tonic::Status {
            tonic::Status::invalid_argument(format!("Invalid value for field `{}`: {}", field, err))
        }

        fn missing_field(field: &str) -> tonic::Status {
            tonic::Status::invalid_argument(format!("Missing required field `{}`", field))
        }

        """
        )

    def array_element(self, name: str, itemtype) -> tuple:
        if isinstance(itemtype, CompositeField):
            return ("s.try_into()", True)

        typ = itemtype.typename
        return {
            "hex": ("hex::encode(s)", False),
            "u8": (
                f'u8::try_from(s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "u16": (
                f'u16::try_from(s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "u32": ("s", False),
            "txid": ("hex::encode(s)", False),
            "secret": (
                f'cln_rpc::primitives::Secret::try_from(s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "hash": (
                f'Sha256::from_slice(&s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "short_channel_id": (
                f'cln_rpc::primitives::ShortChannelId::from_str(&s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "short_channel_id_dir": (
                f'cln_rpc::primitives::ShortChannelIdDir::from_str(&s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "pubkey": (
                f'PublicKey::from_slice(&s).map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "outpoint": (
                f's.try_into().map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "outputdesc": (
                f's.try_into().map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "feerate": (
                f's.try_into().map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
            "proof_field": (
                f's.try_into().map_err(|e| invalid_argument("{name}", e))',
                True,
            ),
        }.get(typ, ("s.into()", False))

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
        impl TryFrom<pb::{pbname}> for {prefix}::{field.typename} {{
            type Error = tonic::Status;
            fn try_from(c: pb::{pbname}) -> Result<Self, Self::Error> {{
                Ok(Self {{
        """
        )

        for f in field.fields:
            name = f.normalized()
            if f.omit():
                continue

            if isinstance(f, ArrayField):
                typ = f.itemtype.typename

                # TODO fix properly
                if typ in ["ListtransactionsTransactionsType"]:
                    continue
                if name == "state_changes":
                    self.write(" state_changes: None,")
                    continue

                elem, fallible = self.array_element(name, f.itemtype)
                if not f.optional:
                    if fallible:
                        self.write(
                            f"{name}: c.{name}.into_iter().map(|s| {elem}).collect::<Result<Vec<_>, tonic::Status>>()?, // Rule #4\n",
                            numindent=3,
                        )
                    else:
                        self.write(
                            f"{name}: c.{name}.into_iter().map(|s| {elem}).collect(), // Rule #4\n",
                            numindent=3,
                        )
                else:
                    if fallible:
                        self.write(
                            f"{name}: Some(c.{name}.into_iter().map(|s| {elem}).collect::<Result<Vec<_>, tonic::Status>>()?), // Rule #4\n",
                            numindent=3,
                        )
                    else:
                        self.write(
                            f"{name}: Some(c.{name}.into_iter().map(|s| {elem}).collect()), // Rule #4\n",
                            numindent=3,
                        )

            elif isinstance(f, EnumField):
                if f.path == "ListPeers.peers[].channels[].htlcs[].state":
                    continue
                if not f.optional:
                    self.write(
                        f'{name}: c.{name}.try_into().map_err(|e| invalid_argument("{name}", e))?,\n',
                        numindent=3,
                    )
                else:
                    self.write(
                        f'{name}: c.{name}.map(|v| v.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?,\n',
                        numindent=3,
                    )

            elif isinstance(f, PrimitiveField):
                typ = f.typename + ("?" if f.optional else "")
                # We may need to reduce or increase the size of some
                # types, or have some conversion such as hex-decoding.
                # Also includes the `Some()` that grpc requires for
                # non-native types.

                if name == "scriptPubKey":
                    name = "script_pub_key"

                rhs = {
                    "u8": f'u8::try_from(c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "u8?": f'c.{name}.map(|v| u8::try_from(v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "u16": f'u16::try_from(c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "u16?": f'c.{name}.map(|v| u16::try_from(v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "hex": f"hex::encode(&c.{name})",
                    "hex?": f"c.{name}.map(|v| hex::encode(v))",
                    "txid?": f"c.{name}.map(|v| hex::encode(v))",
                    "pubkey": f'PublicKey::from_slice(&c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "pubkey?": f'c.{name}.map(|v| PublicKey::from_slice(&v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "msat": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.into()',
                    "msat?": f"c.{name}.map(|a| a.into())",
                    "msat_or_all": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "msat_or_all?": f'c.{name}.map(|a| a.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "msat_or_any": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "msat_or_any?": f'c.{name}.map(|a| a.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "sat": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.into()',
                    "sat?": f"c.{name}.map(|a| a.into())",
                    "sat_or_all": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "sat_or_all?": f'c.{name}.map(|a| a.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "feerate": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "feerate?": f'c.{name}.map(|a| a.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "outpoint?": f'c.{name}.map(|a| a.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "RoutehintList?": f'c.{name}.map(|rl| rl.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "DecodeRoutehintList?": f'c.{name}.map(|drl| drl.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "short_channel_id": f'cln_rpc::primitives::ShortChannelId::from_str(&c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "short_channel_id?": f'c.{name}.map(|v| cln_rpc::primitives::ShortChannelId::from_str(&v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "short_channel_id_dir": f'cln_rpc::primitives::ShortChannelIdDir::from_str(&c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "short_channel_id_dir?": f'c.{name}.map(|v| cln_rpc::primitives::ShortChannelIdDir::from_str(&v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "secret": f'c.{name}.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "secret?": f'c.{name}.map(|v| v.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "hash": f'Sha256::from_slice(&c.{name}).map_err(|e| invalid_argument("{name}", e))?',
                    "hash?": f'c.{name}.map(|v| Sha256::from_slice(&v).map_err(|e| invalid_argument("{name}", e))).transpose()?',
                    "txid": f"hex::encode(&c.{name})",
                    "TlvStream?": f"c.{name}.map(|s| s.into())",
                    "string_map": f'c.{name}.ok_or_else(|| missing_field("{name}"))?',
                    "string_map?": f"Some(c.{name})",
                    "json_object_or_array": f'c.{name}.ok_or_else(|| missing_field("{name}"))?',
                    "json_object_or_array?": f"Some(c.{name})",
                    "json_scalar": f'c.{name}.ok_or_else(|| missing_field("{name}"))?',
                    "json_scalar?": f"Some(c.{name})",
                    "proof_field": f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into().map_err(|e| invalid_argument("{name}", e))?',
                    "proof_field?": f'c.{name}.map(|v| v.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?',
                }.get(
                    typ,
                    f"c.{name}",  # default to just assignment
                )
                self.write(f"{name}: {rhs}, // Rule #1 for type {typ}\n", numindent=3)

            elif isinstance(f, CompositeField):
                if not f.optional:
                    rhs = (
                        f'c.{name}.ok_or_else(|| missing_field("{name}"))?.try_into()?'
                    )
                else:
                    rhs = f"c.{name}.map(|v| v.try_into()).transpose()?"
                self.write(f"{name}: {rhs},\n", numindent=3)

        self.write(
            f"""\
                }})
            }}
        }}

        """
        )
