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

        assert m.get('added', None) is not None or f.added is not None, f"Field {f.path} does not have an `added` annotation"

        # We do not allow the added and deprecated flags to be
        # modified after the fact.
        assert f.added is None or f.added == m['added']
        assert f.deprecated is None or f.deprecated == m.get('deprecated', None)

        if f.added is None:
            f.added = m['added']
        if f.deprecated is None:
            f.deprecated = m.get('deprecated', None)

        # Backfill the metadata using the annotation
        self.meta['model-field-versions'][f.path] = {
            'added': f.added,
            'deprecated': f.deprecated,
        }

