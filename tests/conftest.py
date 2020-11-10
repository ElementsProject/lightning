import pytest


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
