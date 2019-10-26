from pyln.client import Millisatoshi


def test_sum_radd():
    result = sum([Millisatoshi(1), Millisatoshi(2), Millisatoshi(3)])
    assert int(result) == 6
