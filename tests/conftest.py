import pytest
import os

from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND, VALGRIND, SLOW_MACHINE


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
    if "slow_test" in item.keywords and VALGRIND and SLOW_MACHINE:
        pytest.skip("Skipping slow tests under VALGRIND")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """Add environment variables to JUnit XML report.

    This hook runs on the master node in pytest-xdist to add properties
    directly to the JUnit XML report. This works around the limitation
    that record_testsuite_property doesn't work with pytest-xdist.

    We use tryfirst=True so we run before the junitxml plugin writes the file.

    See: https://github.com/pytest-dev/pytest/issues/7767
    """
    # Check if we're on the master node (not a worker)
    # Workers have the workeroutput attribute
    if hasattr(session.config, "workeroutput"):
        return

    # Find the LogXML instance among registered plugins
    # We need to search through all plugins because it's not directly accessible
    xml = None
    for plugin in session.config.pluginmanager.get_plugins():
        if hasattr(plugin, "add_global_property"):
            xml = plugin
            break

    if xml is None:
        return

    # List of environment variables to include in the report
    include = [
        "GITHUB_ACTION_REPOSITORY",
        "GITHUB_EVENT_NAME",
        "GITHUB_HEAD_REF",
        "GITHUB_REF_NAME",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_NUMBER",
        "RUNNER_ARCH",
        "RUNNER_OS",
    ]

    # Add properties to the XML report
    for name in include:
        if name in os.environ:
            xml.add_global_property(name, os.environ[name])
