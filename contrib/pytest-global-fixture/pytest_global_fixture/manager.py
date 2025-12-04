import threading
import importlib
import sys
from typing import Dict
from .base import InfrastructureService


class ServiceManager:
    """
    Runs on the Master process.
    Manages the lifecycle of services and exposes them via XML-RPC.
    """

    def __init__(self):
        self._services: Dict[str, InfrastructureService] = {}  # Map path -> Instance
        self._lock = threading.Lock()

    def _load_class(self, class_path: str) -> InfrastructureService:
        """
        Dynamically imports a class from a string 'module.path:ClassName'.
        """
        try:
            module_name, class_name = class_path.split(":")
        except ValueError:
            raise ValueError(f"Invalid format '{class_path}'. Expected 'module:Class'")

        try:
            # Ensure the current directory is in path so we can import local tests
            if "." not in sys.path:
                sys.path.insert(0, ".")

            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
            return cls()  # Instantiate
        except (ImportError, AttributeError) as e:
            raise RuntimeError(f"Could not load service class '{class_path}': {e}")

    # --- RPC Exposed Methods ---

    def rpc_provision(self, class_path: str, tenant_id: str) -> Dict:
        """
        Idempotent method to start a global service (if needed) and create a tenant.
        """
        with self._lock:
            # 1. Lazy Load & Start Global
            if class_path not in self._services:
                print(f"[Coordinator] Dynamically loading: {class_path}")
                service = self._load_class(class_path)

                print(f"[Coordinator] Starting Global Resource: {class_path}")
                try:
                    service.start_global()
                except Exception as e:
                    print(f"[Coordinator] Failed to start {class_path}: {e}")
                    raise e

                self._services[class_path] = service

            service = self._services[class_path]

            # 2. Create Tenant
            print(f"[Coordinator] Provisioning tenant '{tenant_id}' on {class_path}")
            try:
                config = service.create_tenant(tenant_id)
                return config
            except Exception as e:
                print(f"[Coordinator] Failed to create tenant {tenant_id}: {e}")
                raise e

    def rpc_deprovision(self, class_path: str, tenant_id: str) -> bool:
        """
        Removes a tenant.
        """
        print(f"[Coordinator] De-Provisioning tenant '{tenant_id}' on {class_path}")
        with self._lock:
            service = self._services.get(class_path)
            if service:
                try:
                    service.remove_tenant(tenant_id)
                    return True
                except Exception as e:
                    print(f"[Coordinator] Error removing tenant {tenant_id}: {e}")
        return False

    def teardown_all(self):
        """
        Stop all global services.
        """
        print("\n[Coordinator] Shutting down all global resources...")
        for name, service in self._services.items():
            try:
                print(f"[Coordinator] Stopping {name}")
                service.stop_global()
            except Exception as e:
                print(f"[Coordinator] Error stopping {name}: {e}")
