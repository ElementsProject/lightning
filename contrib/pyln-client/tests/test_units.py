from pyln.client import Millisatoshi


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
