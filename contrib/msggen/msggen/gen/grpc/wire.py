"""Keep the generated protobuf wire format stable across schema changes.

Every field number msggen emits is recorded in `.msggen.json` under
`grpc-wire-contract` together with its label and type. When the JSON
schema later implies a different label or type for that number, we keep
emitting the recorded one if the difference can be bridged in the Rust
conversion code, and refuse to generate otherwise.
"""

import re
from typing import Any, Dict, Optional

SCALARS = {
    "double",
    "float",
    "int32",
    "int64",
    "uint32",
    "uint64",
    "sint32",
    "sint64",
    "fixed32",
    "fixed64",
    "sfixed32",
    "sfixed64",
    "bool",
    "string",
    "bytes",
}

UNSIGNED_WIDTH = {"uint32": 32, "uint64": 64}

# Sat-denominated types that replaced msat-denominated ones. The value
# moves to a new field number and the old number stays as a deprecated
# msat field.
SAT_LEGACY = {"AmountSat": "Amount", "AmountSatOrAll": "AmountOrAll"}


class WireCompatError(Exception):
    pass


class RenumberedField:
    """Key for the new field number of a renumbered field."""

    def __init__(self, path: str):
        self.path = f"{path}#sat"


class WireState:
    """Results of the proto generation that the Rust converters need.

    `pinned` maps field paths whose proto label or type differs from
    the schema to `{"proto": desc, "schema": desc}`. `legacy` maps
    renumbered field paths to their deprecated msat field.
    """

    def __init__(self):
        self.pinned: Dict[str, Dict[str, Dict[str, str]]] = {}
        self.legacy: Dict[str, Dict[str, Any]] = {}


def ensure_meta(meta: Dict[str, Any]) -> None:
    meta.setdefault("grpc-wire-contract", {})
    meta.setdefault("grpc-legacy-fields", {})


def parse_proto(text: str, enums=()) -> Dict[str, Dict[int, Dict[str, str]]]:
    """Extract `{message: {number: {label, type}}}` from a node.proto.

    Types of generated messages are recorded as "message" and enum
    types as "enum", matching what `GrpcGenerator.wire_desc` produces.
    """
    messages: Dict[str, Dict[int, Dict[str, str]]] = {}
    enum_names = set(enums)
    stack = []
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"(message|enum|service) (\w+) \{", s)
        if m:
            stack.append(m.groups())
            if m.group(1) == "message":
                messages.setdefault(m.group(2), {})
            elif m.group(1) == "enum":
                enum_names.add(m.group(2))
            continue
        if s == "}" and stack:
            stack.pop()
            continue
        if not stack or stack[-1][0] != "message":
            continue
        m = re.match(r"(optional |repeated )?(map<[\w, ]+>|[\w.]+) (\w+) = (\d+)", s)
        if m:
            label = (m.group(1) or "plain").strip()
            messages[stack[-1][1]][int(m.group(4))] = {
                "label": label,
                "type": m.group(2),
            }

    for fields in messages.values():
        for desc in fields.values():
            if desc["type"] in messages:
                desc["type"] = "message"
            elif desc["type"] in enum_names:
                desc["type"] = "enum"
    return messages


def released_contract(texts) -> Dict[str, Dict[str, str]]:
    """Build `grpc-wire-contract` from the released `.proto` sources.

    `texts` is the list of proto files of one release. Labels and types
    are taken as released, and enum and message types are recorded by
    kind, so the result compares directly with the recorded contract.
    """
    enums, messages = set(), set()
    for text in texts:
        enums.update(re.findall(r"^\s*enum (\w+) \{", text, re.M))
        messages.update(re.findall(r"^\s*message (\w+) \{", text, re.M))

    contract: Dict[str, Dict[str, str]] = {}
    for text in texts:
        for msg, fields in parse_proto(text, enums=enums).items():
            if msg not in messages:
                continue
            contract.setdefault(msg, {}).update(
                {str(n): pack(desc) for n, desc in fields.items()}
            )
    return contract


def is_scalar(desc: Dict[str, str]) -> bool:
    return desc["type"] in SCALARS or desc["type"] == "enum"


def pack(desc: Dict[str, str]) -> str:
    return f"{desc['label']} {desc['type']}"


def unpack(value: str) -> Dict[str, str]:
    label, typename = value.split(" ", 1)
    return {"label": label, "type": typename}


def resolve(
    path: str,
    schema_type: Optional[str],
    recorded: Dict[str, str],
    current: Dict[str, str],
) -> Dict[str, Any]:
    """Decide what to emit for a field number.

    Returns the descriptor to emit, plus `renumber: True` if the value
    has to move to a new field number.
    """
    if (recorded["label"] == "repeated") != (current["label"] == "repeated"):
        raise WireCompatError(
            f"{path}: cannot change between repeated and non-repeated "
            f"({recorded['label']} {recorded['type']} -> "
            f"{current['label']} {current['type']})"
        )

    # Adding `optional` is wire compatible. Dropping it would turn
    # 0/""/false into "absent", so once released it stays.
    if "optional" in (recorded["label"], current["label"]):
        label = "optional"
    else:
        label = recorded["label"]

    rt, ct = recorded["type"], current["type"]
    if rt == ct:
        return {"label": label, "type": ct}

    if current["label"] != "repeated":
        if rt in UNSIGNED_WIDTH and ct in UNSIGNED_WIDTH:
            if UNSIGNED_WIDTH[rt] > UNSIGNED_WIDTH[ct]:
                return {"label": label, "type": rt}
        if rt == "double" and ct == "uint32":
            return {"label": label, "type": rt}
        if rt == "string" and ct == "bytes" and schema_type == "pubkey":
            return {"label": label, "type": rt}
        if SAT_LEGACY.get(ct) == rt:
            return {"label": current["label"], "type": ct, "renumber": True}

    raise WireCompatError(
        f"{path}: the schema now maps to `{current['label']} {ct}` but "
        f"the field number was released as `{recorded['label']} {rt}`. "
        f"This is not wire compatible: teach msggen.gen.grpc.wire how to "
        f"bridge it, or give the field a new name."
    )
