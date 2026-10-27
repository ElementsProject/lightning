# A grpc model
import re

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

        fn double_to_u32(field: &str, v: f64) -> Result<u32, tonic::Status> {
            if v.fract() != 0.0 || !(0.0..=u32::MAX as f64).contains(&v) {
                return Err(invalid_argument(field, format!("{} is not a u32", v)));
            }
            Ok(v as u32)
        }

        fn msat_to_sat(field: &str, a: pb::Amount) -> Result<cln_rpc::primitives::AmountSat, tonic::Status> {
            cln_rpc::primitives::AmountSat::from_msat(a.msat)
                .map_err(|e| invalid_argument(field, e))
        }

        fn msat_or_all_to_sat(field: &str, a: pb::AmountOrAll) -> Result<cln_rpc::primitives::AmountSatOrAll, tonic::Status> {
            use cln_rpc::primitives::{AmountSat, AmountSatOrAll};
            Ok(match a.value {
                Some(pb::amount_or_all::Value::Amount(a)) => AmountSatOrAll::AmountSat(
                    AmountSat::from_msat(a.msat).map_err(|e| invalid_argument(field, e))?,
                ),
                Some(pb::amount_or_all::Value::All(_)) => AmountSatOrAll::All,
                None => return Err(invalid_argument(field, "AmountOrAll is empty")),
            })
        }

        fn sat_or_legacy<N, L, T>(
            field: &str,
            new: Option<N>,
            legacy: Option<L>,
            conv_new: impl FnOnce(N) -> Result<T, tonic::Status>,
            conv_legacy: impl FnOnce(L) -> Result<T, tonic::Status>,
        ) -> Result<Option<T>, tonic::Status> {
            match (new, legacy) {
                (Some(_), Some(_)) => Err(tonic::Status::invalid_argument(format!(
                    "Fields `{field}_sat` and deprecated `{field}` are mutually exclusive"
                ))),
                (Some(n), None) => conv_new(n).map(Some),
                (None, Some(l)) => conv_legacy(l).map(Some),
                (None, None) => Ok(None),
            }
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

    def with_pinned(self, f, key: str, name: str, rhs: str) -> str:
        """Bridge a field whose proto label/type is pinned to the released
        one by substituting `c.{name}` in `rhs` (which is written against
        the schema-implied proto type) with a converted value."""
        pin = self.state.pinned.get(key)
        if pin is None:
            return rhs
        proto, schema = pin["proto"], pin["schema"]
        v = f"c.{name}"

        # Released as plain, so 0/""/false is all an old client can send
        # to mean "not set".
        if proto["label"] == "plain" and schema["label"] == "optional":
            if proto["type"] == "bool":
                v = f"Some({v}).filter(|v| *v)"
            elif proto["type"] in ("string", "bytes"):
                v = f"Some({v}).filter(|v| !v.is_empty())"
            else:
                v = f"Some({v}).filter(|v| *v != Default::default())"
        elif proto["label"] == "optional" and schema["label"] == "plain":
            v = f'{v}.ok_or_else(|| missing_field("{name}"))?'

        optional = schema["label"] == "optional"
        if proto["type"] != schema["type"]:
            conv = {
                (
                    "uint64",
                    "uint32",
                ): f'|v| u32::try_from(v).map_err(|e| invalid_argument("{name}", e))',
                ("double", "uint32"): f'|v| double_to_u32("{name}", v)',
                (
                    "string",
                    "bytes",
                ): f'|v| hex::decode(v).map_err(|e| invalid_argument("{name}", e))',
            }[(proto["type"], schema["type"])]
            if optional:
                v = f"{v}.map({conv}).transpose()?"
            else:
                v = f"({conv})({v})?"

        return re.sub(rf"\bc\.{name}\b", lambda _: f"({v})", rhs)

    def legacy_rhs(self, key: str, f, name: str) -> str:
        legacy = self.state.legacy[key]
        new = f"c.{legacy['new_name']}"
        old = f"c.{name}"
        if f.typename == "sat":
            conv_new = "|a| Ok(a.into())"
            conv_old = f'|a| msat_to_sat("{name}", a)'
        else:
            conv_new = f'|a| a.try_into().map_err(|e| invalid_argument("{legacy["new_name"]}", e))'
            conv_old = f'|a| msat_or_all_to_sat("{name}", a)'
        rhs = f'sat_or_legacy("{name}", {new}, {old}, {conv_new}, {conv_old})?'
        if not f.optional:
            rhs += f'.ok_or_else(|| missing_field("{name}"))?'
        return rhs

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

        pbname = self.to_camel_case(str(field.typename))
        has_deprecated = any(
            [
                f.deprecated or f"{pbname}.{f.path}" in self.state.legacy
                for f in field.fields
            ]
        )
        deprecated = ",deprecated" if has_deprecated else ""
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
            key = f"{pbname}.{f.path}"
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
                    rhs = f'c.{name}.try_into().map_err(|e| invalid_argument("{name}", e))?'
                else:
                    rhs = f'c.{name}.map(|v| v.try_into().map_err(|e| invalid_argument("{name}", e))).transpose()?'
                self.write(
                    f"{name}: {self.with_pinned(f, key, name, rhs)},\n", numindent=3
                )

            elif isinstance(f, PrimitiveField) and key in self.state.legacy:
                self.write(f"{name}: {self.legacy_rhs(key, f, name)},\n", numindent=3)

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
                rhs = self.with_pinned(f, key, name, rhs)
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
