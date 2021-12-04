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
    amount = Millisatoshi("100msat") * 0.1
    assert int(amount) == 10
    amount = Millisatoshi("10msat") * 0.1
    assert int(amount) == 1


def test_zero():
    # zero amounts are of course valid
    amount = Millisatoshi("0btc")
    assert int(amount) == 0
    amount = Millisatoshi("0sat")
    assert int(amount) == 0
    amount = Millisatoshi("0msat")
    assert int(amount) == 0

    # zero floating amount as well
    amount = Millisatoshi("0.0btc")
    assert int(amount) == 0
    amount = Millisatoshi("0.0sat")
    assert int(amount) == 0
    amount = Millisatoshi("0.0msat")
    assert int(amount) == 0

    # also anything multiplied by zero
    amount = Millisatoshi("1btc") * 0
    assert int(amount) == 0
    amount = Millisatoshi("1sat") * 0
    assert int(amount) == 0
    amount = Millisatoshi("1msat") * 0
    assert int(amount) == 0

    # and multiplied by a floating zero
    amount = Millisatoshi("1btc") * 0.0
    assert int(amount) == 0
    amount = Millisatoshi("1sat") * 0.0
    assert int(amount) == 0
    amount = Millisatoshi("1msat") * 0.0
    assert int(amount) == 0


def test_round_zero():
    # everything below 1msat should round down to zero
    amount = Millisatoshi("1msat") * 0.9
    assert int(amount) == 0
    amount = Millisatoshi("10msat") * 0.09
    assert int(amount) == 0
    amount = Millisatoshi("100msat") * 0.009
    assert int(amount) == 0
    amount = Millisatoshi("1000msat") * 0.0009
    assert int(amount) == 0

    amount = Millisatoshi("1sat") * 0.0009
    assert int(amount) == 0
    amount = Millisatoshi("0.1sat") * 0.009
    assert int(amount) == 0
    amount = Millisatoshi("0.01sat") * 0.09
    assert int(amount) == 0
    amount = Millisatoshi("0.001sat") * 0.9
    assert int(amount) == 0

    amount = Millisatoshi("10sat") * 0.00009
    assert int(amount) == 0
    amount = Millisatoshi("100sat") * 0.000009
    assert int(amount) == 0
    amount = Millisatoshi("1000sat") * 0.0000009
    assert int(amount) == 0
    amount = Millisatoshi("10000sat") * 0.00000009
    assert int(amount) == 0
    amount = Millisatoshi("10000sat") * 0.00000009
    assert int(amount) == 0

    amount = Millisatoshi("1btc") * 0.000000000009
    assert int(amount) == 0
    amount = Millisatoshi("0.1btc") * 0.00000000009
    assert int(amount) == 0
    amount = Millisatoshi("0.01btc") * 0.0000000009
    assert int(amount) == 0
    amount = Millisatoshi("0.001btc") * 0.000000009
    assert int(amount) == 0
    amount = Millisatoshi("0.0001btc") * 0.00000009
    assert int(amount) == 0
    amount = Millisatoshi("0.00001btc") * 0.0000009
    assert int(amount) == 0
    amount = Millisatoshi("0.000001btc") * 0.000009
    assert int(amount) == 0
    amount = Millisatoshi("0.0000001btc") * 0.00009
    assert int(amount) == 0
    amount = Millisatoshi("0.00000001btc") * 0.0009
    assert int(amount) == 0
    amount = Millisatoshi("0.000000001btc") * 0.009
    assert int(amount) == 0
    amount = Millisatoshi("0.0000000001btc") * 0.09
    assert int(amount) == 0
    amount = Millisatoshi("0.00000000001btc") * 0.9
    assert int(amount) == 0


def test_round_down():
    # sub msat significatns should be floored
    amount = Millisatoshi("2msat") * 0.9
    assert int(amount) == 1
    amount = Millisatoshi("20msat") * 0.09
    assert int(amount) == 1
    amount = Millisatoshi("200msat") * 0.009
    assert int(amount) == 1
    amount = Millisatoshi("2000msat") * 0.0009
    assert int(amount) == 1

    amount = Millisatoshi("2sat") * 0.0009
    assert int(amount) == 1
    amount = Millisatoshi("0.2sat") * 0.009
    assert int(amount) == 1
    amount = Millisatoshi("0.02sat") * 0.09
    assert int(amount) == 1
    amount = Millisatoshi("0.002sat") * 0.9
    assert int(amount) == 1

    amount = Millisatoshi("20sat") * 0.00009
    assert int(amount) == 1
    amount = Millisatoshi("200sat") * 0.000009
    assert int(amount) == 1
    amount = Millisatoshi("2000sat") * 0.0000009
    assert int(amount) == 1
    amount = Millisatoshi("20000sat") * 0.00000009
    assert int(amount) == 1
    amount = Millisatoshi("20000sat") * 0.00000009
    assert int(amount) == 1

    amount = Millisatoshi("2btc") * 0.000000000009
    assert int(amount) == 1
    amount = Millisatoshi("0.2btc") * 0.00000000009
    assert int(amount) == 1
    amount = Millisatoshi("0.02btc") * 0.0000000009
    assert int(amount) == 1
    amount = Millisatoshi("0.002btc") * 0.000000009
    assert int(amount) == 1
    amount = Millisatoshi("0.0002btc") * 0.00000009
    assert int(amount) == 1
    amount = Millisatoshi("0.00002btc") * 0.0000009
    assert int(amount) == 1
    amount = Millisatoshi("0.000002btc") * 0.000009
    assert int(amount) == 1
    amount = Millisatoshi("0.0000002btc") * 0.00009
    assert int(amount) == 1
    amount = Millisatoshi("0.00000002btc") * 0.0009
    assert int(amount) == 1
    amount = Millisatoshi("0.000000002btc") * 0.009
    assert int(amount) == 1
    amount = Millisatoshi("0.0000000002btc") * 0.09
    assert int(amount) == 1
    amount = Millisatoshi("0.00000000002btc") * 0.9
    assert int(amount) == 1


def test_nosubmsat():
    # sub millisatoshi are not a concept yet
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi("0.1msat")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi(".1msat")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi("0.0001sat")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi(".0001sat")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi("0.000000000001btc")
    with pytest.raises(ValueError, match='Millisatoshi must be a whole number'):
        Millisatoshi(".000000000001btc")


def test_nonegative():
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1btc")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1.0btc")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-0.1btc")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-.1btc")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1sat")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1.0sat")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-0.1sat")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-.1sat")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1msat")
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("-1.0msat")

    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1msat") * -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1msat") * -42
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1sat") * -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1btc") * -1

    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1msat") / -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1msat") / -0.5
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1sat") / -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1btc") / -1

    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1msat") // -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1sat") // -1
    with pytest.raises(ValueError, match='Millisatoshi must be >= 0'):
        Millisatoshi("1btc") // -1


def test_mul():
    # msat * num := msat
    amount = Millisatoshi(21) * 2
    assert isinstance(amount, Millisatoshi)
    assert amount == Millisatoshi(42)
    amount = Millisatoshi(21) * 2.5
    assert amount == Millisatoshi(52)

    # msat * msat := msat^2  (which is not supported)
    with pytest.raises(TypeError, match="not supported"):
        Millisatoshi(21) * Millisatoshi(2)


def test_div():
    # msat / num := msat
    amount = Millisatoshi(42) / 2
    assert isinstance(amount, Millisatoshi)
    assert amount == Millisatoshi(21)
    amount = Millisatoshi(42) / 2.6
    assert amount == Millisatoshi(16)

    # msat / msat := num   (float ratio)
    amount = Millisatoshi(42) / Millisatoshi(2)
    assert isinstance(amount, float)
    assert amount == 21.0
    amount = Millisatoshi(8) / Millisatoshi(5)
    assert amount == 1.6

    # msat // num := msat
    amount = Millisatoshi(42) // 2
    assert isinstance(amount, Millisatoshi)
    assert amount == Millisatoshi(21)

    # msat // msat := num
    amount = Millisatoshi(42) // Millisatoshi(3)
    assert isinstance(amount, int)
    assert amount == 14
    amount = Millisatoshi(42) // Millisatoshi(3)
    assert amount == 14
    amount = Millisatoshi(42) // Millisatoshi(4)
    assert amount == 10


def test_init():
    # Note: Ongoing Discussion, hence the `with pytest.raises`.
    # https://github.com/ElementsProject/lightning/pull/4273#discussion_r540369093
    #
    # Initialization with a float should be possible:
    # Millisatoshi(5) / 2 currently works, and removes the half msat.
    # So Millisatoshi(5 / 2) should be the same.
    amount = Millisatoshi(5) / 2
    assert amount == Millisatoshi(2)
    with pytest.raises(TypeError, match="Millisatoshi by float is currently not supported"):
        assert amount == Millisatoshi(5 / 2)

    ratio = Millisatoshi(8) / Millisatoshi(5)
    assert isinstance(ratio, float)
    with pytest.raises(TypeError, match="Millisatoshi by float is currently not supported"):
        assert Millisatoshi(ratio) == Millisatoshi(8 / 5)

    # Check that init by a round float is allowed.
    # Required by some existing tests: tests/test_wallet.py::test_txprepare
    amount = Millisatoshi(42.0)
    assert amount == 42
