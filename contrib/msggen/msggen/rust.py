import logging

from .model import (ArrayField, Command, CompositeField, EnumField,
                    PrimitiveField)

logger = logging.getLogger(__name__)

# The following words need to be changed, otherwise they'd clash with
# built-in keywords.
keywords = ["in", "type"]


header = """use serde::{Deserialize, Serialize};

type hex = String;
type string = String;
type boolean = bool;
type txid = String;
type short_channel_id = String;
type pubkey = String;
type msat = String;
type number = i64;
type signature = String;

"""


def normalize_varname(field):
    """Make sure that the variable name of this field is valid.
    """
    # Dashes are not valid names
    field.path = field.path.replace("-", "_")
    return field


def gen_field(field):
    field = normalize_varname(field)

    if isinstance(field, Command):
        return gen_command(field)
    elif isinstance(field, CompositeField):
        return gen_composite(field)
    elif isinstance(field, EnumField):
        return gen_enum(field)
    elif isinstance(field, ArrayField):
        return gen_array(field)
    elif isinstance(field, PrimitiveField):
        return gen_primitive(field)
    else:
        raise ValueError(f"Unmanaged type {field}")


def gen_enum(e):
    defi, decl = "", ""

    decl += f"#[derive(Debug, Deserialize, Serialize)]\n#[allow(non_camel_case_types)]\npub enum {e.typename} {{\n"
    for v in e.values:
        decl += f"\t{v.upper() if v is not None else 'NONE'},\n"
    decl += "}\n\n"

    name = e.name if e.name not in keywords else f"_{e.name}"

    defi = f"\t{name}: {e.typename},\n"

    return defi, decl


def gen_primitive(p):
    defi, decl = "", ""

    defi = f"\t{p.name}: {p.typename},\n"

    return defi, decl


def gen_array(a):
    name = a.name.replace("[]", "")
    logger.debug(f"Generating array field {a.name} -> {name} ({a.path})")

    _, decl = gen_field(a.itemtype)

    if isinstance(a.itemtype, PrimitiveField):
        itemtype = a.itemtype.typename
    elif isinstance(a.itemtype, CompositeField):
        itemtype = a.itemtype.typename
    elif isinstance(a.itemtype, EnumField):
        itemtype = a.itemtype.typename

    defi = f"\tpub {name}: {'Vec<'*a.dims}{itemtype}{'>'*a.dims},\n"

    return (defi, decl)


def gen_composite(c) -> (str, str):
    logger.debug(f"Generating composite field {c.name} ({c.path})")
    fields = []
    for f in c.fields:
        fields.append(gen_field(f))

    r = "".join([f[1] for f in fields])

    r += f"""#[derive(Clone, Debug, Deserialize, Serialize)]\npub struct {c.typename} {{\n"""

    r += "".join([f[0] for f in fields])

    r += "}\n\n"
    return ("", r)


def gen_command(c) -> str:
    """A command is just the a composite type, with no definition, but a declaration."""
    _, decl = gen_composite(c)
    return ("", header + decl)


def gen_rust(command: Command) -> str:
    return gen_command(command)[1]
