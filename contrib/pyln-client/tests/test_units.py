from pyln.client import Millisatoshi
import pytest  # type: ignore


def test_to_approx_str():
    amount = Millisatoshi('10000000sat')
    assert amount.to_approx_str() == "0.1btc"
    amount = Millisatoshi('1000000sat')
    assert amount.to_approx_str() == "0.01btc"
    amount = Millisatoshi('100000sat')
    assert amount.to_approx_str() == "0.001btc"
    amount = Millisatoshi('10000sat')
    assert amount.to_approx_str() == "10000sat"
    amount = Millisatoshi('1000sat')
    assert amount.to_approx_str() == "1000sat"
    amount = Millisatoshi('100msat')
    assert amount.to_approx_str() == "0.1sat"

    # also test significant rounding
    amount = Millisatoshi('10001234sat')
    assert amount.to_approx_str() == "0.1btc"
    amount = Millisatoshi('1234sat')
    assert amount.to_approx_str(3) == "1234sat"  # note: no rounding
    amount = Millisatoshi('1234sat')
    assert amount.to_approx_str(2) == "1234sat"  # note: no rounding
    amount = Millisatoshi('1230sat')
    assert amount.to_approx_str(2) == "1230sat"  # note: no rounding
    amount = Millisatoshi('12345678sat')
    assert amount.to_approx_str() == "0.123btc"
    amount = Millisatoshi('12345678sat')
    assert amount.to_approx_str(1) == "0.1btc"
    amount = Millisatoshi('15345678sat')
    assert amount.to_approx_str(1) == "0.2btc"
    amount = Millisatoshi('1200000000sat')
    assert amount.to_approx_str() == "12btc"
    amount = Millisatoshi('1200000000sat')
    assert amount.to_approx_str(1) == "12btc"  # note: no rounding


def test_floats():
    # test parsing amounts from floating number strings
    amount = Millisatoshi("0.01btc")
    assert amount.to_satoshi() == 10**6
    amount = Millisatoshi("1.01btc")
    assert amount.to_satoshi() == 10**8 + 10**6
    amount = Millisatoshi("0.1sat")
    assert int(amount) == 100
    amount = Millisatoshi("0.01sat")
    assert int(amount) == 10
    amount = Millisatoshi("1.1sat")
    assert int(amount) == 1100

    # test floating point arithmetic
    amount = Millisatoshi("1000msat") * 0.1
    assert int(amount) == 100

    # sub millisatoshi are not a concept yet
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        amount = Millisatoshi("0.000000000001btc")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        amount = Millisatoshi("0.0001sat")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        amount = Millisatoshi("0.1msat")
