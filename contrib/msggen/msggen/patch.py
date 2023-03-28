from abc import ABC
from msggen import model


class Patch(ABC):
    """A patch that can be applied to an in-memory model

    This effectively post-processes the in-memory model to ensure the
    invariants are satisfied.

    """

    def visit(self, field: model.Field) -> None:
        """Gets called for each node in the model.
        """
        pass

    def apply(self, service: model.Service) -> None:
        """Apply this patch to the model by calling `visit` in
        pre-order on each node in the schema tree.

        """
        def recurse(f: model.Field):
            # First recurse if we have further type definitions
            if isinstance(f, model.ArrayField):
                self.visit(f.itemtype)
                recurse(f.itemtype)
            elif isinstance(f, model.CompositeField):
                for c in f.fields:
                    self.visit(c)
                    recurse(c)
            # Now visit ourselves
            self.visit(f)
        for m in service.methods:
            recurse(m.request)
            recurse(m.response)


class VersionAnnotationPatch(Patch):
    """Annotates fields with the version they were added or deprecated if not specified.

    A patch is used so we don't have to annotate all fields that
    existed prior to the introduction of the `added` and `deprecated`
    fields, and uses the `.msggen.json` file to remember which fields
    are known, and which ones are new. For existing fields we just
    want a default value, while for new fields we want to error if the
    author did not annotate them manually.

    """

    def __init__(self, meta) -> None:
        """Create a patch that can annotate `added` and `deprecated`
        """
        self.meta = meta

    def visit(self, f: model.Field) -> None:
        m = self.meta['model-field-versions'].get(f.path, {})

        # The following lines are used to backfill fields that predate
        # the introduction, so they need to use a default version to
        # mark. These are stored in `.msggen.json` only, and we use
        # the default value only on the first run. Code left commented
        # to show how it was done
        # if f.added is None and 'added' not in m:
        #     m['added'] = 'pre-v0.10.1'

        added = m.get('added', None)
        deprecated = m.get('deprecated', None)

        assert added or not f.added, f"Field {f.path} does not have an `added` annotation"

        # We do not allow the added and deprecated flags to be
        # modified after the fact.
        if f.added and added and f.added != m['added']:
            raise ValueError(f"Field {f.path} changed `added` annotation: {f.added} != {m['added']}")

        if f.deprecated and deprecated and f.deprecated != deprecated:
            raise ValueError(f"Field {f.path} changed `deprecated` annotation: {f.deprecated} != {m['deprecated']}")

        if f.added is None:
            f.added = added
        if f.deprecated is None:
            f.deprecated = deprecated

        # Backfill the metadata using the annotation
        self.meta['model-field-versions'][f.path] = {
            'added': f.added,
            'deprecated': f.deprecated,
        }


class OptionalPatch(Patch):
    """Annotates fields with `.optional`

    Optional fields are either non-required fields, or fields that
    were not required in prior versions. This latter case covers the
    deprecation and addition for schema evolution
    """

    versions = [
        'pre-v0.10.1',  # Dummy versions collecting all fields that predate the versioning.
        'v0.10.1',
        'v0.10.2',
        'v0.11.0',
        'v0.12.0',
        'v0.12.1',
        'v22.11',
        'v23.02',
        'v23.05',
    ]
    # Oldest supported versions. Bump this if you no longer want to
    # support older versions, and you want to make required fields
    # more stringent.
    supported = 'v0.12.0'

    def visit(self, f: model.Field) -> None:
        if f.added not in self.versions:
            raise ValueError(f"Version {f.added} in unknown, please add it to {__file__}")
        if f.deprecated and f.deprecated not in self.versions:
            raise ValueError(f"Version {f.deprecated} in unknown, please add it to {__file__}")

        idx = (
            self.versions.index(self.supported),
            len(self.versions) - 1,
        )
        # Default to false, and then overwrite it if required.
        f.optional = False
        if not f.required:
            f.optional = True

        if self.versions.index(f.added) > idx[0]:
            f.optional = True

        if f.deprecated and self.versions.index(f.deprecated) < idx[1]:
            f.optional = True
