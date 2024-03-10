from pyln.testing.version import Version


def test_version_parsing():
    cases = [
        ("v24.02", Version(24, 2)),
        ("v23.11.2", Version(23, 11, 2)),
    ]

    for test_in, test_out in cases:
        v = Version.from_str(test_in)
        assert test_out == v
