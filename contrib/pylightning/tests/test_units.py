from decimal import Decimal
from lightning import Millisatoshi


def test_units():
    amount = Millisatoshi(42)
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42msat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42sat')
    assert amount.millisatoshis == 42 * 1000
    amount = Millisatoshi('42mbtc')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**8
    # also with decimals
    amount = Millisatoshi('0.042sat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('0.42mbtc')
    assert amount.millisatoshis == 42 * 1000 * 10**3
    amount = Millisatoshi('0.42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('.42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**6


def test_misc():
    amount = Millisatoshi('42mbtc')
    assert amount.to_mbtc() == Decimal(42)
    assert amount.to_mbtc_str() == '42.00000mbtc'
    amount = Millisatoshi('0.42mbtc')
    assert amount.to_mbtc() == Decimal('0.42')
    assert amount.to_mbtc_str() == '0.42000mbtc'


def test_to_approx_str():
    amount = Millisatoshi('10000000sat')
    assert amount.to_approx_str() == "0.1btc"
    amount = Millisatoshi('1000000sat')
    assert amount.to_approx_str() == "10mbtc"
    amount = Millisatoshi('100000sat')
    assert amount.to_approx_str() == "1mbtc"
    amount = Millisatoshi('10000sat')
    assert amount.to_approx_str() == "0.1mbtc"
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
    assert amount.to_approx_str() == "123mbtc"
    amount = Millisatoshi('12345678sat')
    assert amount.to_approx_str(1) == "0.1btc"
    amount = Millisatoshi('15345678sat')
    assert amount.to_approx_str(1) == "0.2btc"
    amount = Millisatoshi('1200000000sat')
    assert amount.to_approx_str() == "12btc"
    amount = Millisatoshi('1200000000sat')
    assert amount.to_approx_str(1) == "12btc"  # note: no rounding
