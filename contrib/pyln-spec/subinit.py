# This is the same __init__.py for all bolt dirs.
from .gen import csv, text, desc
from .gen_version import __version__, __gitversion__
from .bolt import namespace
import sys

__all__ = [
    'csv',
    'text',
    'desc',
    'namespace',
    '__version__',
    '__gitversion__',
]

mod = sys.modules[__name__]
for d in namespace.subtypes, namespace.tlvtypes, namespace.messagetypes:
    for name in d:
        setattr(mod, name, d[name])
        __all__.append(name)
