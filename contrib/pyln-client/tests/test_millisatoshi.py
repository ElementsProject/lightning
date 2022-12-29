import pytest
from pyln.client import Millisatoshi


def test_sum_radd():
    result = sum([Millisatoshi(1), Millisatoshi(2), Millisatoshi(3)])
    assert int(result) == 6


def test_compare_int():
    # Test that we can compare msat to int numbers
    assert Millisatoshi(10) == 10
    assert Millisatoshi(10) > 9
    assert Millisatoshi(10) >= 9
    assert Millisatoshi(10) < 11
    assert Millisatoshi(10) <= 11

    # Same as above but check that the order doesn't matter
    assert 10 == Millisatoshi(10)
    assert 9 < Millisatoshi(10)
    assert 9 <= Millisatoshi(10)
    assert 11 > Millisatoshi(10)
    assert 11 >= Millisatoshi(10)

    # Test that we can't accidentally compare msat to float
    assert Millisatoshi(10) != 10.0
    with pytest.raises(AttributeError):
        assert Millisatoshi(10) > 9.0
    with pytest.raises(AttributeError):
        assert Millisatoshi(10) >= 9.0
    with pytest.raises(AttributeError):
        assert Millisatoshi(10) < 11.0
    with pytest.raises(AttributeError):
        assert Millisatoshi(10) <= 11.0

    # ... and again that order does not matter
    assert 10.0 != Millisatoshi(10)
    with pytest.raises(AttributeError):
        assert 9.0 < Millisatoshi(10)
    with pytest.raises(AttributeError):
        assert 9.0 <= Millisatoshi(10)
    with pytest.raises(AttributeError):
        assert 11.0 > Millisatoshi(10)
    with pytest.raises(AttributeError):
        assert 11.0 >= Millisatoshi(10)
