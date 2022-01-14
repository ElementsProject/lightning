from typing import List, Union, Optional
import logging

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

        name = name.replace(' ', '_').replace('-', '_')
        return name

    def __str__(self):
        return self.name


class Field:
    def __init__(self, path, description):
        self.path = path
        self.description = description
        self.required = False

    @property
    def name(self):
        return FieldName(self.path.split(".")[-1])

    def __str__(self):
        return f"Field[path={self.path}, required={self.required}]"

    def __repr__(self):
        return str(self)

    def normalized(self):
        return self.name.normalized()


class Service:
    """Top level class that wraps all the RPC methods.
    """
    def __init__(self, name: str, methods=None):
        self.name = name
        self.methods = [] if methods is None else methods

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
        return types


class Method:
    def __init__(self, name: str, request: Field, response: Field):
        self.name = name
        self.request = request
        self.response = response


class CompositeField(Field):
    def __init__(self, typename, fields, path, description):
        Field.__init__(self, path, description)
        self.typename = typename
        self.fields = fields

    @classmethod
    def from_js(cls, js, path):
        typename = path2type(path)

        properties = js["properties"]
        # Ok, let's flatten the conditional properties. We do this by
        # reformatting the outer conditions into the `allOf` format.
        top = {
            'then': {'properties': js.get('then', {}).get('properties', [])},
            'else': {'properties': js.get('else', {}).get('properties', [])},
        }
        # Yes, this is ugly, but walking nested dicts always is.
        for a in [top] + js.get('allOf', []):
            var = a.get('then', {})
            props = var.get('properties', None)
            if isinstance(props, dict):
                for k, v in props.items():
                    if k not in properties:
                        properties[k] = v
            var = a.get('else', {})
            props = var.get('properties', None)
            if isinstance(props, dict):
                for k, v in props.items():
                    if k not in properties:
                        properties[k] = v

        # Identify required fields
        required = js.get("required", [])
        fields = []
        for fname, ftype in properties.items():
            field = None
            desc = ftype["description"] if "description" in ftype else ""
            fpath = f"{path}.{fname}"

            if ftype.get("deprecated", False):
                logger.warning(f"Unmanaged {fpath}, it is deprecated")
                continue

            if "type" not in ftype:
                logger.warning(f"Unmanaged {fpath}, it doesn't have a type")
                continue

            # TODO Remove the `['string', 'null']` match once
            # `listpeers.peers[].channels[].closer` no longer has this
            # type
            if ftype["type"] == ["string", "null"]:
                ftype["type"] = "string"

            # Peek into the type so we know how to decode it
            if ftype["type"] in ["string", ["string", "null"]] and "enum" in ftype:
                field = EnumField.from_js(ftype, fpath)

            elif ftype["type"] == "object":
                field = CompositeField.from_js(ftype, fpath)

            elif ftype["type"] == "array":
                field = ArrayField.from_js(fpath, ftype)

            elif ftype["type"] in PrimitiveField.types:
                field = PrimitiveField(ftype["type"], fpath, desc)

            else:
                logger.warning(
                    f"Unmanaged {path}, type {ftype} is not mapped in the object model"
                )

            if field is not None:
                field.required = fname in required
                fields.append(field)
                logger.debug(field)

        return CompositeField(
            typename, fields, path, js["description"] if "description" in js else ""
        )

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

    def normalized(self):
        return self.variant.replace(' ', '_').replace('-', '_').upper()


class EnumField(Field):
    def __init__(self, typename, values, path, description):
        Field.__init__(self, path, description)
        self.typename = typename
        self.values = values
        self.variants = [EnumVariant(v) for v in self.values]

    @classmethod
    def from_js(cls, js, path):
        # Transform the path into something that is a valid TypeName
        typename = path2type(path)
        return EnumField(
            typename,
            values=filter(lambda i: i is not None, js["enum"]),
            path=path,
            description=js["description"] if "description" in js else "",
        )

    def __str__(self):
        values = ",".join([v for v in self.values if v is not None])
        return f"Enum[path={self.path}, required={self.required}, values=[{values}]]"


class PrimitiveField(Field):
    # Leaf types that we expect the binding languages to provide
    types = [
        "boolean",
        "u32",
        "u64",
        "u8",
        "string",
        "pubkey",
        "signature",
        "msat",
        "hex",
        "short_channel_id",
        "txid",
        "integer",
        "u16",
        "number",
    ]

    def __init__(self, typename, path, description):
        Field.__init__(self, path, description)
        self.typename = typename

    def __str__(self):
        return f"Primitive[path={self.path}, required={self.required}, type={self.typename}]"


class ArrayField(Field):
    def __init__(self, itemtype, dims, path, description):
        Field.__init__(self, path, description)
        self.itemtype = itemtype
        self.dims = dims
        self.path = path

    @classmethod
    def from_js(cls, path, js):
        # Determine how nested we are
        dims = 1
        child_js = js["items"]
        while child_js["type"] == "array":
            dims += 1
            child_js = child_js["items"]

        path += "[]" * dims
        if child_js["type"] == "object":
            itemtype = CompositeField.from_js(child_js, path)

        elif child_js["type"] == "string" and "enum" in child_js:
            itemtype = EnumField.from_js(child_js, path)

        elif child_js["type"] in PrimitiveField.types:
            itemtype = PrimitiveField(
                child_js["type"], path, child_js.get("description", "")
            )

        logger.debug(f"Array path={path} dims={dims}, type={itemtype}")
        return ArrayField(
            itemtype, dims=dims, path=path, description=js.get("description", "")
        )

    def normalized(self):
        # Strip the '[]' that we use to signal an array. The name
        # itself doesn't need this.
        return Field.normalized(self)[:-2]


class Command:
    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    def __str__(self):
        fieldnames = ",".join([f.path.split(".")[-1] for f in self.fields])
        return f"Command[name={self.name}, fields=[{fieldnames}]]"


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
