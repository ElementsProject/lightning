import pytest

from pyln.testing.utils import DEVELOPER, EXPERIMENTAL_DUAL_FUND


# This function is based upon the example of how to
# "[make] test result information available in fixtures" at:
#  https://pytest.org/latest/example/simple.html#making-test-result-information-available-in-fixtures
# and:
#  https://github.com/pytest-dev/pytest/issues/288
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


def pytest_configure(config):
    config.addinivalue_line("markers",
                            "slow_test: slow tests aren't run under Valgrind")
    config.addinivalue_line("markers",
                            "developer: only run when developer is flagged on")
    config.addinivalue_line("markers",
                            "openchannel: Limit this test to only run 'v1' or 'v2' openchannel protocol")


def pytest_runtest_setup(item):
    open_versions = [mark.args[0] for mark in item.iter_markers(name='openchannel')]
    if open_versions:
        if 'v1' not in open_versions and not EXPERIMENTAL_DUAL_FUND:
            pytest.skip('v2-only test, EXPERIMENTAL_DUAL_FUND=0')
        if 'v2' not in open_versions and EXPERIMENTAL_DUAL_FUND:
            pytest.skip('v1-only test, EXPERIMENTAL_DUAL_FUND=1')
    else:  # If there's no openchannel marker, skip if EXP_DF
        if EXPERIMENTAL_DUAL_FUND:
            pytest.skip('v1-only test, EXPERIMENTAL_DUAL_FUND=1')

    for mark in item.iter_markers(name='developer'):
        if not DEVELOPER:
            if len(mark.args):
                pytest.skip('!DEVELOPER: {}'.format(mark.args[0]))
            else:
                pytest.skip('!DEVELOPER: Requires DEVELOPER=1')
