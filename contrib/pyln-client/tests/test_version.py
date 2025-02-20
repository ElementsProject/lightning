from pyln.client.version import NodeVersion, VersionSpec, _NodeVersionPart, _CompareSpec


def test_create_version():
    # These are the strings returned by `lightningd --version`
    _ = NodeVersion("v24.02")
    _ = NodeVersion("23.08.1")


def test_parse_parts():
    assert _NodeVersionPart.parse("2rc2") == _NodeVersionPart(2, "rc2")
    assert _NodeVersionPart.parse("0rc1") == _NodeVersionPart(0, "rc1")
    assert _NodeVersionPart.parse("2") == _NodeVersionPart(2, None)
    assert _NodeVersionPart.parse("2").text is None


def test_version_to_parts():

    assert NodeVersion("v24.02rc1").to_parts() == [
        _NodeVersionPart(24),
        _NodeVersionPart(2, "rc1"),
    ]

    assert NodeVersion("v24.02.1").to_parts() == [
        _NodeVersionPart(24),
        _NodeVersionPart(2),
        _NodeVersionPart(1),
    ]


def test_equality_classes_in_node_versions():
    assert NodeVersion("v24.02") == NodeVersion("v24.02")
    assert NodeVersion("v24.02") == NodeVersion("v24.02rc1")
    assert NodeVersion("v24.02rc1") == NodeVersion("v24.02")

    assert NodeVersion("v24.02") != NodeVersion("v24.02.1")
    assert NodeVersion("v24.02rc1") != NodeVersion("v24.02.1")
    assert NodeVersion("v23.10") != NodeVersion("v23.02")


def test_inequality_of_node_versions():
    assert not NodeVersion("v24.02.1") > NodeVersion("v24.02.1")
    assert NodeVersion("v24.02.1") > NodeVersion("v24.02")
    assert NodeVersion("v24.02.1") > NodeVersion("v24.02rc1")
    assert NodeVersion("v24.02.1") > NodeVersion("v23.05")

    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02.1")
    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02")
    assert NodeVersion("v24.02.1") >= NodeVersion("v24.02rc1")
    assert NodeVersion("v24.02.1") >= NodeVersion("v23.05")

    assert NodeVersion("v24.02.1") <= NodeVersion("v24.02.1")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v24.02")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v24.02rc1")
    assert not NodeVersion("v24.02.1") <= NodeVersion("v23.05")

    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02.1")
    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02")
    assert not NodeVersion("v24.02.1") < NodeVersion("v24.02rc1")
    assert not NodeVersion("v24.02.1") < NodeVersion("v23.05")


def test_comparision_parse():
    assert _CompareSpec.parse("===v24.02").operator == "==="
    assert _CompareSpec.parse("=v24.02").operator == "="
    assert _CompareSpec.parse("!===v24.02").operator == "!==="
    assert _CompareSpec.parse("!=v24.02").operator == "!="
    assert _CompareSpec.parse(">v24.02").operator == ">"
    assert _CompareSpec.parse("<v24.02").operator == "<"
    assert _CompareSpec.parse(">=v24.02").operator == ">="
    assert _CompareSpec.parse("<=v24.02").operator == "<="


def test_compare_spec_from_string():
    assert VersionSpec.parse("=v24.02").matches("v24.02rc1")
    assert VersionSpec.parse("=v24.02").matches("v24.02")
    assert not VersionSpec.parse("=v24.02").matches("v24.02.1")

    # Yes, I use weird spaces here as a part of the test
    list_spec = VersionSpec.parse(">=    v24.02, !=== v24.02rc1")
    assert list_spec.matches("v24.02")
    assert list_spec.matches("v24.02.1")

    assert not list_spec.matches("v24.02rc1")
    assert not list_spec.matches("v23.11")


def test_ci_modded_version_is_always_latest():
    v1 = NodeVersion("1a86e50-modded")

    assert v1 > NodeVersion("v24.02")
