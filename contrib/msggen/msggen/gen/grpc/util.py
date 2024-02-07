typemap = {
    "boolean": "bool",
    "hex": "bytes",
    "msat": "Amount",
    "msat_or_all": "AmountOrAll",
    "msat_or_any": "AmountOrAny",
    "currency": "string",
    "number": "double",
    "pubkey": "bytes",
    "short_channel_id": "string",
    "signature": "string",
    "string": "string",
    "txid": "bytes",
    "u8": "uint32",  # Yep, this is the smallest integer type in grpc...
    "u32": "uint32",
    "u64": "uint64",
    "s8": "int32",
    "s16": "int32",
    "s32": "int32",
    "s64": "int64",
    "u16": "uint32",  # Yeah, I know...
    "f32": "float",
    "integer": "sint64",
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
