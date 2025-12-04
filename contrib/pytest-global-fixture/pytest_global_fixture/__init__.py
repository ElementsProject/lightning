"""
pytest-global-fixture: A pytest plugin for globally shared infrastructure resources.
"""

from .base import InfrastructureService
from .postgres_service import NativePostgresService

__all__ = [
    'InfrastructureService',
    'NativePostgresService',
]
