from pyln.client.version import NodeVersion


def test_create_version():
    # These are the strings returned by `lightningd --version`
    _ = NodeVersion("v24.11-232-g5a76c7a")
    _ = NodeVersion("v24.11-225-gda793e6-modded")
    _ = NodeVersion("v24.11")
    _ = NodeVersion("vd6fa78c")


def test_equality_classes_in_node_versions():
    assert NodeVersion("v24.02") == NodeVersion("v24.02")
    assert NodeVersion("v24.02") == NodeVersion("24.02")
    assert NodeVersion("v24.02-225") == NodeVersion("v24.02")

    assert NodeVersion("v24.02") == NodeVersion("v24.02rc1")
    assert NodeVersion("v24.11-217-g77989b1-modded") == NodeVersion("v24.11")
    assert NodeVersion("vd6fa78c") == NodeVersion("vabcdefg")


def test_inequality_of_node_versions():
    assert not NodeVersion("v24.02.1") > NodeVersion("v24.02.1")
    assert NodeVersion("v24.02.1") > NodeVersion("v24.02")
    assert NodeVersion("v24.02.1") > NodeVersion("v24.02rc1")
    assert NodeVersion("v24.02.1") > NodeVersion("v23.05")
    assert NodeVersion("v24.05") > NodeVersion("v24.02")
    assert NodeVersion("vd6fa78c") > NodeVersion("v26.02")

    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02.1")
    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02")
    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02rc1")
    assert NodeVersion("v24.02.1") >= NodeVersion("v23.05")
    assert NodeVersion("v24.05") >= NodeVersion("v24.02")
    assert NodeVersion("vd6fa78c") >= NodeVersion("v26.02")

    assert NodeVersion("v24.02.1") <= NodeVersion("v24.02.1")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v24.02")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v24.02rc1")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v23.05")
    assert not NodeVersion("v24.05") <= NodeVersion("v24.02")
    assert not NodeVersion("vd6fa78c") <= NodeVersion("v26.02")

    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02.1")
    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02")
    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02rc1")
    assert not NodeVersion("v24.02.1") < NodeVersion("v23.05")
    assert not NodeVersion("v24.05") < NodeVersion("v24.02")
    assert not NodeVersion("vd6fa78c") < NodeVersion("v26.02")
