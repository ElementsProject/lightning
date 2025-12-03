from abc import ABC, abstractmethod
from typing import Any, Dict


class InfrastructureService(ABC):
    """
    Interface that all shared resources must implement.
    These methods run exclusively on the Coordinator (Main) Process.
    """

    @abstractmethod
    def start_global(self) -> None:
        """
        Initialize the heavy, global resource (e.g., Docker container).
        This is called exactly once, the first time a worker requests this service.
        """
        pass

    @abstractmethod
    def stop_global(self) -> None:
        """
        Teardown the global resource.
        Called at the very end of the pytest session.
        """
        pass

    @abstractmethod
    def create_tenant(self, tenant_id: str) -> Dict[str, Any]:
        """
        Create a logical isolation unit (Database, Schema, VHost).

        Args:
            tenant_id: A unique string identifier for the requester (e.g., 'gw0_test_uuid').

        Returns:
            A JSON-serializable dictionary containing connection details
            (host, port, user, password, db_name, etc.)
        """
        pass

    @abstractmethod
    def remove_tenant(self, tenant_id: str) -> None:
        """
        Clean up the logical isolation unit.
        """
        pass
