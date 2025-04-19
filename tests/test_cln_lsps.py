from fixtures import *  # noqa: F401,F403
import os
from pathlib import Path

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")


def test_lsps0_listprotocols(node_factory):
    lsps_client_plugin = os.path.join(Path.cwd(), "target", RUST_PROFILE, "cln-lsps-client")
    lsps_service_plugin = os.path.join(Path.cwd(), "target", RUST_PROFILE, "cln-lsps-service")

    l1, l2 = node_factory.get_nodes(2, opts=[
        {"plugin": str(lsps_client_plugin)}, {"plugin": str(lsps_service_plugin)}
    ])

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(peer=l2.info['id'])
    assert res
