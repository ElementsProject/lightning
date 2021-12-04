from pyln.testing.fixtures import *  # noqa: F401 F403


def test_peers(node_factory):
    l1, l2 = node_factory.line_graph(2)
