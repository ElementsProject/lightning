from fixtures import *  # noqa: F401,F403
import os

RUST_PROFILE = os.environ.get("RUST_PROFILE", "debug")


def test_lsps_service_disabled(node_factory):
    """By default we disable the LSPS service plugin.

    It should only be enabled if we explicitly set the config option
    `lsps-service=True`.
    """

    l1 = node_factory.get_node(1)
    l1.daemon.is_in_log("`lsps-service` not enabled")


def test_lsps0_listprotocols(node_factory):
    l1, l2 = node_factory.get_nodes(2, opts=[
        {"dev-lsps-client-enabled": None}, {"dev-lsps-service-enabled": None}
    ])

    # We don't need a channel to query for lsps services
    node_factory.join_nodes([l1, l2], fundchannel=False)

    res = l1.rpc.lsps_listprotocols(peer=l2.info['id'])
    assert res
