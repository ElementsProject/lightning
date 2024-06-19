from pyln.client.clnutils import cln_parse_rpcversion


def test_rpcversion():
    foo = cln_parse_rpcversion("0.11.2")
    assert foo[0] == 0
    assert foo[1] == 11
    assert foo[2] == 2

    foo = cln_parse_rpcversion("0.11.2rc2-modded")
    assert foo[0] == 0
    assert foo[1] == 11
    assert foo[2] == 2

    foo = cln_parse_rpcversion("22.11")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 0

    foo = cln_parse_rpcversion("22.11rc1")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 0

    foo = cln_parse_rpcversion("22.11rc1-modded")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 0

    foo = cln_parse_rpcversion("22.11-modded")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 0

    foo = cln_parse_rpcversion("22.11.0")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 0

    foo = cln_parse_rpcversion("22.11.1")
    assert foo[0] == 22
    assert foo[1] == 11
    assert foo[2] == 1
