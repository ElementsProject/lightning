# This is the same __init__.py for all bolt dirs.
from .csv import csv
from .text import text, desc
from .gen_csv_version import __csv_version__
from .gen_version import __base_version__, __post_version__, __gitversion__
from .bolt import namespace
import sys

# eg. 1.0.1.137.
__version__ = '{}.{}.{}'.format(__base_version__, __csv_version__, __post_version__)

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
