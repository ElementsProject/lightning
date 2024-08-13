from typing import List, Union, Optional
import logging
from copy import copy

logger = logging.getLogger(__name__)


def path2type(path):
    typename = "".join([s.capitalize() for s in path.replace("[]", "").split(".")])
    return typename


class FieldName:
    def __init__(self, name):
        self.name = name

    def normalized(self):
        name = {
            "type": "item_type"
        }.get(self.name, self.name)

        name = name.replace(' ', '_').replace('-', '_').replace('[]', '').replace("/", "_")
        return name

    def __str__(self):
        return self.name


class TypeName:
    def __init__(self, name: Optional[str]):
        if name is None:
            raise ValueError("empty typename")
        self.name = name

    def __str__(self) -> str:
        """Return the normalized typename."""
        return (
            self.name
            .replace(' ', '_')
            .replace('-', '')
            .replace('/', '_')
        )

    def __repr__(self) -> str:
        return f"Typename[raw={self.name}, str={self}"

    def __iadd__(self, other):
        self.name += str(other)
        return self

    def __lt__(self, other) -> bool:
        return str(self.name) < str(other)


class MethodName(TypeName):
    """A class encapsulating the naming rules for methods. """


class Field:
    def __init__(
            self,
            path,
            description,
            added=None,
            deprecated=None
    ):
        self.path = path
        self.description = description
        self.added = added
        self.deprecated = deprecated
        self.required = False

        # Are we going to omit this field when generating bindings?
        # This usually means that the field either doesn't make sense
        # to convert or that msggen cannot handle converting this
        # field and its children yet.
        self.omitted = False

        self.type_override: Optional[str] = None

    def __lt__(self, other):
        return self.path < other.path

    def __eq__(self, other):
        return self.path == other.path

    def __iter__(self):
        yield self.path

    @property
    def name(self):
        return FieldName(self.path.split(".")[-1])

    def __str__(self):
        return f"Field[path={self.path}, required={self.required}]"

    def __repr__(self):
        return str(self)

    def normalized(self):
        return self.name.normalized()

    def capitalized(self):
        return self.name.capitalized()

    def omit(self):
        """Returns true if we should not consider this field in our model.

        This can be either because the field is redundant, or because
        msggen cannot currently handle it. The field (and it's type if
        it's composite) will not be materialized in the generated
        bindings and converters.

        It is mainly switched on and off in the OverridePatch which is
        the central location where we manage overrides and omissions.

        """
        return self.omitted

    def override(self, default: Optional[str] = None) -> Optional[str]:
        """Provide a type that should be used instead of the inferred one.

        This is useful if for shared types that we don't want to
        generate multiple times, and for enums that can result in
        naming clashes in the grpc model (enum variantss must be
        uniquely name in the top-level scope...).

        It is mainly switched on and off in the OverridePatch which is
        the central location where we manage overrides and omissions.

        """
        return self.type_override if self.type_override else default


class Service:
    """Top level class that wraps all the RPC methods.
    """
    def __init__(self, name: str, methods=None, notifications=None):
        self.name: str = name
        self.methods: List[Method] = [] if methods is None else methods
        self.notifications: List[Notification] = [] if notifications is None else notifications

        # If we require linking with some external files we'll add
        # them here so the generator can use them.
        self.includes: List[str] = []

    def gather_types(self):
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
        for method in self.methods:
            types.extend([method.request, method.response])
            for field in method.request.fields:
                types.extend(gather_subfields(field))
            for field in method.response.fields:
                types.extend(gather_subfields(field))

        for notification in self.notifications:
            types.extend([notification.request])
            for field in notification.request.fields:
                types.extend(gather_subfields(field))
            for field in notification.response.fields:
                types.extend(gather_subfields(field))

        return types


class Notification:
    def __init__(self, name: str, typename: str, request: Field, response: Field):
        self.name = name
        self.typename = typename
        self.request = request
        self.response = response


class Method:
    def __init__(self, name: str, request: Field, response: Field):
        self.name = name
        self.name_raw = name
        self.request = request
        self.response = response


class CompositeField(Field):
    def __init__(
            self,
            typename: TypeName,
            fields,
            path,
            description,
            added,
            deprecated
    ):
        Field.__init__(
            self,
            path,
            description,
            added=added,
            deprecated=deprecated
        )
        self.typename = typename
        self.fields = fields

    @classmethod
    def from_js(cls, js, path):
        typename = TypeName(path2type(path))

        properties = js.get("properties", {})
        # Ok, let's flatten the conditional properties. We do this by
        # reformatting the outer conditions into the `allOf` format.
        top = {
            'then': {'properties': js.get('then', {}).get('properties', [])},
            'else': {'properties': js.get('else', {}).get('properties', [])},
        }
        # Yes, this is ugly, but walking nested dicts always is.

        def merge_dicts(dict1, dict2):
            merged_dict = {}
            for key in set(dict1.keys()) | set(dict2.keys()):
                if key in dict1 and key in dict2:
                    if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                        merged_dict[key] = merge_dicts(dict1[key], dict2[key])
                    else:
                        if isinstance(dict1[key], list) and isinstance(dict2[key], list):
                            merged_dict[key] = sorted(list(set(dict1[key]).union(set(dict2[key]))))
                        elif key in dict1:
                            merged_dict[key] = dict1[key]
                        else:
                            merged_dict[key] = dict2[key]
                elif key in dict1:
                    merged_dict[key] = dict1[key]
                else:
                    merged_dict[key] = dict2[key]
            return merged_dict

        for a in [top] + js.get('allOf', []):
            var = a.get('then', {})
            props = var.get('properties', {})
            if isinstance(props, dict):
                for k, v in props.items():
                    if properties != {}:
                        if k in properties:
                            properties[k] = merge_dicts(properties[k], v)
                        else:
                            properties[k] = v
            var = a.get('else', {})
            props = var.get('properties', {})
            if isinstance(props, dict):
                for k, v in props.items():
                    if properties != {}:
                        if k in properties:
                            properties[k] = merge_dicts(properties[k], v)
                        else:
                            properties[k] = v
        # Identify required fields
        required = js.get("required", [])
        fields = []
        for fname, ftype in properties.items():
            field = None
            desc = ftype["description"] if "description" in ftype else ""
            fpath = f"{path}.{fname}"
            added = ftype.get('added', None)
            deprecated = ftype.get('deprecated', None)

            if fpath in overrides:
                field = copy(overrides[fpath])
                field.path = fpath
                field.description = desc
                if isinstance(field, ArrayField):
                    field.itemtype.path = fpath

            elif "type" not in ftype:
                logger.warning(f"Unmanaged {fpath}, it doesn't have a type")
                continue

            # Peek into the type so we know how to decode it
            elif ftype["type"] in ["string", ["string", "null"]] and "enum" in ftype:
                field = EnumField.from_js(ftype, fpath)

            elif ftype["type"] == "object":
                field = CompositeField.from_js(ftype, fpath)

            elif ftype["type"] == "array":
                field = ArrayField.from_js(fpath, ftype)

            elif ftype["type"] in PrimitiveField.types:
                field = PrimitiveField(ftype["type"], fpath, desc, added=added, deprecated=deprecated)

            else:
                logger.warning(
                    f"Unmanaged {path}, type {ftype} is not mapped in the object model"
                )

            if field is not None:
                field.deprecated = ftype.get("deprecated", None)
                field.required = fname in required
                fields.append(field)
                logger.debug(field)

        return CompositeField(
            typename, fields, path, js["description"] if "description" in js else "", added=js.get('added', None), deprecated=js.get('deprecated', None)
        )

    def sort(self):
        self.fields = sorted(self.fields)

    def __str__(self):
        fieldnames = ",".join([f.path.split(".")[-1] for f in self.fields])
        return f"CompositeField[name={self.path}, fields=[{fieldnames}]]"


class EnumVariant(Field):
    """A variant of an enum with helpers for normalization of the display.
    """
    def __init__(self, variant: Optional[str]):
        self.variant = variant

    def __str__(self):
        return self.variant

    def __lt__(self, other):
        return self.variant < other.variant

    def __eq__(self, other):
        return self.variant == other.variant

    def normalized(self):
        return self.variant.replace(' ', '_').replace('-', '_').replace("/", "_").upper()


class EnumField(Field):
    def __init__(self, typename: TypeName, values, path, description, added, deprecated):
        Field.__init__(self, path, description, added=added, deprecated=deprecated)
        self.typename = typename
        self.values = values
        self.variants = [EnumVariant(v) for v in self.values]

    @classmethod
    def from_js(cls, js, path):
        # Transform the path into something that is a valid TypeName
        typename = TypeName(path2type(path))
        return EnumField(
            typename,
            values=filter(lambda i: i is not None, js["enum"]),
            path=path,
            description=js["description"] if "description" in js else "",
            added=js.get('added', None),
            deprecated=js.get('deprecated', None),
        )

    def __str__(self):
        values = ",".join([v for v in self.values if v is not None])
        return f"Enum[path={self.path}, required={self.required}, values=[{values}]]"


class UnionField(Field):
    """A type that can be one of a number of types.

    Corresponds to the `oneOf` type in JSON-Schema, an `enum` in Rust
    and a `oneof` in protobuf.

    """
    def __init__(self, path, description, variants, added, deprecated):
        Field.__init__(self, path, description, added=added, deprecated=deprecated)
        self.variants = variants
        self.typename = path2type(path)

    @classmethod
    def from_js(cls, js, path):
        assert('oneOf' in js)
        variants = []
        for child_js in js['oneOf']:
            if child_js["type"] == "object":
                itemtype = CompositeField.from_js(child_js, path)

            elif child_js["type"] == "string" and "enum" in child_js:
                itemtype = EnumField.from_js(child_js, path)

            elif child_js["type"] in PrimitiveField.types:
                itemtype = PrimitiveField(
                    child_js["type"], path, child_js.get("description", "")
                )
            elif child_js["type"] == "array":
                itemtype = ArrayField.from_js(path, child_js)
            variants.append(itemtype)

        return UnionField(path, js.get('description', None), variants)


class PrimitiveField(Field):
    # Leaf types that we expect the binding languages to provide
    types = [
        "boolean",
        "u32",
        "u64",
        "u8",
        "f32",
        "float",
        "string",
        "pubkey",
        "signature",
        "msat",
        "msat_or_any",
        "msat_or_all",
        "sat",
        "sat_or_all",
        "currency",
        "hex",
        "short_channel_id",
        "short_channel_id_dir",
        "txid",
        "integer",
        "outpoint",
        "u16",
        "number",
        "feerate",
        "utxo",  # A string representing the tuple (txid, outnum)
        "outputdesc",  # A dict that maps an address to an amount (bitcoind style)
        "secret",
        "bip340sig",
        "hash",
    ]

    def __init__(self, typename, path, description, added, deprecated):
        Field.__init__(self, path, description, added=added, deprecated=deprecated)
        self.typename = typename

    def __str__(self):
        return f"Primitive[path={self.path}, required={self.required}, type={self.typename}]"


class ArrayField(Field):
    def __init__(self, itemtype, dims, path, description, added, deprecated):
        Field.__init__(self, path, description, added=added, deprecated=deprecated)
        self.itemtype = itemtype
        self.dims = dims
        self.path = path

    @classmethod
    def from_js(cls, path, js):
        # Determine how nested we are
        dims = 1
        child_js = js["items"]
        while child_js.get("type", None) == "array":
            dims += 1
            child_js = child_js["items"]

        path += "[]" * dims
        if 'oneOf' in child_js:
            assert('type' not in child_js)
            itemtype = UnionField.from_js(child_js, path)

        elif child_js["type"] == "object":
            itemtype = CompositeField.from_js(child_js, path)

        elif child_js["type"] == "string" and "enum" in child_js:
            itemtype = EnumField.from_js(child_js, path)

        elif child_js["type"] in PrimitiveField.types:
            itemtype = PrimitiveField(
                child_js["type"],
                path,
                child_js.get("description", ""),
                added=child_js.get("added", None),
                deprecated=child_js.get("deprecated", None),
            )

        logger.debug(f"Array path={path} dims={dims}, type={itemtype}")
        return ArrayField(
            itemtype, dims=dims, path=path, description=js.get("description", ""), added=js.get('added', None), deprecated=js.get('deprecated', None)
        )


class Command:
    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    def __str__(self):
        fieldnames = ",".join([f.path.split(".")[-1] for f in self.fields])
        return f"Command[name={self.name}, fields=[{fieldnames}]]"


OfferStringField = PrimitiveField("string", None, None, added=None, deprecated=None)
InvoiceLabelField = PrimitiveField("string", None, None, added=None, deprecated=None)
DatastoreKeyField = ArrayField(itemtype=PrimitiveField("string", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added=None, deprecated=None)
DatastoreUsageKeyField = ArrayField(itemtype=PrimitiveField("string", None, None, added="v23.11", deprecated=None), dims=1, path=None, description=None, added="v23.11", deprecated=None)
InvoiceExposeprivatechannelsField = ArrayField(itemtype=PrimitiveField("short_channel_id", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added=None, deprecated=None)
PayExclude = ArrayField(itemtype=PrimitiveField("string", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added=None, deprecated=None)
RenePayExclude = ArrayField(itemtype=PrimitiveField("string", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added="v24.08", deprecated=None)
RoutehintListField = PrimitiveField(
    "RoutehintList",
    None,
    None,
    added=None,
    deprecated=None
)
SetConfigValField = PrimitiveField("string", None, None, added=None, deprecated=None)
DecodeRoutehintListField = PrimitiveField(
    "DecodeRoutehintList",
    None,
    None,
    added=None,
    deprecated=None
)
CreateRuneRestrictionsField = ArrayField(itemtype=PrimitiveField("string", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added=None, deprecated=None)
CheckRuneParamsField = ArrayField(itemtype=PrimitiveField("string", None, None, added=None, deprecated=None), dims=1, path=None, description=None, added=None, deprecated=None)

# TlvStreams are special, they don't have preset dict-keys, rather
# they can specify `u64` keys pointing to hex payloads. So the schema
# has to rely on additionalProperties to make it work.
TlvStreamField = PrimitiveField(
    "TlvStream",
    None,
    None,
    added=None,
    deprecated=None
)

# Override fields with manually managed types, fieldpath -> field mapping
overrides = {
    'Invoice.label': InvoiceLabelField,
    'DelInvoice.label': InvoiceLabelField,
    'ListInvoices.label': InvoiceLabelField,
    'Datastore.key': DatastoreKeyField,
    'DelDatastore.key': DatastoreKeyField,
    'ListDatastore.key': DatastoreKeyField,
    'Invoice.exposeprivatechannels': InvoiceExposeprivatechannelsField,
    'Pay.exclude': PayExclude,
    'RenePay.exclude': RenePayExclude,
    'KeySend.routehints': RoutehintListField,
    'KeySend.extratlvs': TlvStreamField,
    'Decode.routes': DecodeRoutehintListField,
    'DecodePay.routes': DecodeRoutehintListField,
    'CreateInvoice.label': InvoiceLabelField,
    'DatastoreUsage.key': DatastoreUsageKeyField,
    'WaitInvoice.label': InvoiceLabelField,
    'Offer.recurrence_base': OfferStringField,
    'Offer.amount': OfferStringField,
    'SetConfig.val': SetConfigValField,
    'CreateRune.restrictions': CreateRuneRestrictionsField,
    'CheckRune.params': CheckRuneParamsField,
}


def parse_doc(command, js) -> Union[CompositeField, Command]:
    """Given a command name and its schema, generate the IR model"""
    path = command

    # All our top-level wrappers are objects, right?
    assert js["type"] in ["object", "string"]
    if js["type"] == "string":
        # Special case: stop just returns a string
        return Command(path.capitalize(), [])
    else:
        return CompositeField.from_js(js, path)
