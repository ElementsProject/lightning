from pyln.testing.fixtures import *  # noqa: F401 F403
import pytest


@pytest.mark.parametrize('bitcoind', [False], indirect=True)
def test_unstarted_bitcoind(bitcoind):
    """Taking the fixture unstarted must still tear down cleanly."""
    assert bitcoind.proc is None
    bitcoind.kill()
