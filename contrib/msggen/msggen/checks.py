from abc import ABC
from msggen import model


class Check(ABC):
    """A check is a visitor that throws exceptions on inconsistencies.

    """
    def visit(self, field: model.Field) -> None:
        pass

    def check(self, service: model.Service) -> None:
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


class VersioningCheck(Check):
    """Check that all schemas have the `added` and `deprecated` annotations.
    """
    def visit(self, f: model.Field) -> None:
        if not hasattr(f, "added"):
            raise ValueError(f"Field {f.path} is missing the 'added' annotation")
        if not hasattr(f, "deprecated"):
            raise ValueError(f"Field {f.path} is missing the 'deprecated' annotation")
