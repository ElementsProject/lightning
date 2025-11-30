import pytest
import threading
import uuid
import sys
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import xmlrpc.client
from .manager import ServiceManager

# --- RPC Server Setup (Runs on Master) ---

class QuietXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    """Suppress standard logging from XML-RPC server."""
    def log_message(self, format, *args):
        pass

def pytest_configure(config):
    """
    If this is the Master/Coordinator process, start the RPC server.
    """
    # Check if we are a worker (xdist). If no workerinput, we are Master.
    if not hasattr(config, "workerinput"):
        print("\n" + "="*80)
        print("PYTEST-GLOBAL-FIXTURE: Coordinator mode - managing shared resources")
        print("="*80)
        manager = ServiceManager()
        
        # Bind to port 0 (ephemeral)
        server = SimpleXMLRPCServer(
            ("localhost", 0), 
            requestHandler=QuietXMLRPCRequestHandler, 
            allow_none=True,
            logRequests=False
        )
        server.register_instance(manager)
        
        # Run server in daemon thread
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        
        host, port = server.server_address
        rpc_addr = f"http://{host}:{port}/"
        
        # Store in config to pass to workers/hooks
        config.infra_rpc_addr = rpc_addr
        config.infra_manager = manager
        
        print(f"--- [Coordinator] Infrastructure Manager listening at {rpc_addr} ---")

def pytest_configure_node(node):
    """
    This runs on Master for each Worker node being created.
    Pass the RPC address to the worker.
    """
    node.workerinput["infra_rpc_addr"] = node.config.infra_rpc_addr

def pytest_unconfigure(config):
    """
    Run teardown on Master when session ends.
    """
    if hasattr(config, "infra_manager"):
        config.infra_manager.teardown_all()


# --- Fixture (Runs on Workers) ---

@pytest.fixture(scope="session")
def coordinator_client(request):
    """
    Returns the XML-RPC client to talk to the manager.
    """
    if hasattr(request.config, "workerinput"):
        addr = request.config.workerinput["infra_rpc_addr"]
        worker_id = request.config.workerinput.get("workerid", "unknown")
        print(f"[{worker_id}] PYTEST-GLOBAL-FIXTURE: Worker connecting to coordinator at {addr}")
    else:
        # We are running sequentially (no xdist), or we are the master
        addr = request.config.infra_rpc_addr
        print(f"PYTEST-GLOBAL-FIXTURE: Sequential mode, using coordinator at {addr}")

    return xmlrpc.client.ServerProxy(addr)

@pytest.fixture(scope="function")
def global_resource(request):
    """
    Factory fixture.
    Usage: global_resource("path.to:Class")
    """

    # Get RPC address
    if hasattr(request.config, "workerinput"):
        addr = request.config.workerinput["infra_rpc_addr"]
    else:
        addr = request.config.infra_rpc_addr

    # Track resources created in this scope for cleanup
    created_resources = []

    def _provision(class_path):
        # Create unique tenant ID: "gwX_testName_UUID"
        worker_id = getattr(request.config, "workerinput", {}).get("workerid", "master")
        test_name = request.node.name.replace("[", "_").replace("]", "_")
        # Short uuid for uniqueness
        uid = uuid.uuid4().hex[:6]
        tenant_id = f"{worker_id}_{uid}"

        # Create a new ServerProxy for each call to avoid connection reuse issues
        # This prevents http.client.CannotSendRequest errors in multi-threaded scenarios
        client = xmlrpc.client.ServerProxy(addr)
        config = client.rpc_provision(class_path, tenant_id)

        created_resources.append((class_path, tenant_id))
        return config

    yield _provision

    # Teardown logic
    for class_path, tenant_id in reversed(created_resources):
        try:
            # Create a new client for cleanup too
            client = xmlrpc.client.ServerProxy(addr)
            client.rpc_deprovision(class_path, tenant_id)
        except Exception as e:
            # We print but don't raise, to avoid masking test failures
            print(f"Warning: Failed to deprovision {tenant_id}: {e}")
