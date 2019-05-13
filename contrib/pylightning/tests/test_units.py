from lightning import Millisatoshi
import pytest


def test_units():
    """Test the extended bitcoin unit parser.

    For common Bitcoin currency units see: https://en.bitcoin.it/wiki/Units
    """

    # first we test that we didnt break old functionality with just integer or
    # msat, sat and btc units without whitespaces and plurals
    amount = Millisatoshi(42)
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42msat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42sat')
    assert amount.millisatoshis == 42 * 1000
    amount = Millisatoshi('42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**8
    # also with decimals
    amount = Millisatoshi('0.042sat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('0.42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('.42btc')
    assert amount.millisatoshis == 42 * 1000 * 10**6

    # test whitespacing
    amount = Millisatoshi(' 42msat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42 msat')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42 msat ')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42  sat')
    assert amount.millisatoshis == 42 * 1000
    amount = Millisatoshi('   0.42  btc  ')
    assert amount.millisatoshis == 42 * 1000 * 10**6

    # test extended units
    amount = Millisatoshi('42µbtc')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42ubtc')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42mbtc')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42cbtc')
    assert amount.millisatoshis == 42 * 1000 * 10**6

    # test alternative names
    amount = Millisatoshi('42satoshi')
    assert amount.millisatoshis == 42 * 1000
    amount = Millisatoshi('42finney')
    assert amount.millisatoshis == 42 * 1000 * 10
    amount = Millisatoshi('42bit')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42millibit')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42millie')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42milli')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42bitcent')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('42cent')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('42bitcoin')
    assert amount.millisatoshis == 42 * 1000 * 10**8
    amount = Millisatoshi('42coin')
    assert amount.millisatoshis == 42 * 1000 * 10**8

    # test plurals
    amount = Millisatoshi('42msats')
    assert amount.millisatoshis == 42
    amount = Millisatoshi('42sats')
    assert amount.millisatoshis == 42 * 1000
    amount = Millisatoshi('42btcs')
    assert amount.millisatoshis == 42 * 1000 * 10**8
    amount = Millisatoshi('42µbtcs')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42ubtcs')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42mbtcs')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42cbtcs')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('42finnies')
    assert amount.millisatoshis == 42 * 1000 * 10
    amount = Millisatoshi('42bits')
    assert amount.millisatoshis == 42 * 1000 * 10**2
    amount = Millisatoshi('42millibits')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42millies')
    assert amount.millisatoshis == 42 * 1000 * 10**5
    amount = Millisatoshi('42bitcents')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('42cents')
    assert amount.millisatoshis == 42 * 1000 * 10**6
    amount = Millisatoshi('42bitcoins')
    assert amount.millisatoshis == 42 * 1000 * 10**8
    amount = Millisatoshi('42coins')
    assert amount.millisatoshis == 42 * 1000 * 10**8

    # and finally also test some error cases
    with pytest.raises(TypeError, match=r'Millisatoshi must be.*'):
        amount = Millisatoshi('42abc')
    with pytest.raises(TypeError, match=r'Millisatoshi must be.*'):
        amount = Millisatoshi('.42 abc')
    with pytest.raises(TypeError, match=r'Millisatoshi must be.*'):
        amount = Millisatoshi('4f2 sat')
    with pytest.raises(TypeError, match=r'Millisatoshi must be.*'):
        # hex not supported yet
        amount = Millisatoshi('0x123 sat')


def test_short_str():
    amount = Millisatoshi('10000000sat')
    assert amount.to_short_str() == "0.1btc"
    amount = Millisatoshi('1000000sat')
    assert amount.to_short_str() == "10mbtc"
    amount = Millisatoshi('10000sat')
    assert amount.to_short_str() == "0.1mbtc"
    amount = Millisatoshi('1000sat')
    assert amount.to_short_str() == "10µbtc"

    amount = Millisatoshi('10001234sat')
    assert amount.to_short_str() == "0.1btc"
    amount = Millisatoshi('1234sat')
    assert amount.to_short_str() == "1230sat"
    amount = Millisatoshi('1234sat')
    assert amount.to_short_str(2) == "12µbtc"
    amount = Millisatoshi('12345678sat')
    assert amount.to_short_str() == "123mbtc"
    amount = Millisatoshi('12345678sat')
    assert amount.to_short_str(1) == "0.1btc"
    amount = Millisatoshi('15345678sat')
    assert amount.to_short_str(1) == "0.2btc"
