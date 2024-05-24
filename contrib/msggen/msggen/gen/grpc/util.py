# A grpc model
import re

from msggen.model import TypeName

typemap = {
    "boolean": "bool",
    "hex": "bytes",
    "msat": "Amount",
    "msat_or_all": "AmountOrAll",
    "msat_or_any": "AmountOrAny",
    "sat": "Amount",
    "sat_or_all": "AmountOrAll",
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
    "InvoiceRequest": "CreateInvoiceRequest",
}


def snake_to_camel(snake_str: str):
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


def notification_typename_overrides(typename: str):
    if isinstance(typename, TypeName):
        return_class = TypeName
    else:
        return_class = str

    if str(typename).startswith("Connect"):
        return return_class(f"Peer{typename}")
    else:
        return typename


def camel_to_snake(camel_case: str):
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", camel_case).lower()
    snake = snake.replace("-", "")
    return snake
