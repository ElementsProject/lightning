import fcntl
import os
import pytest
import shutil
import tempfile
import time

from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND, VALGRIND, SLOW_MACHINE


def _mem_available_mb():
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        return None
    return None


def _other_workers_active(gate_dir, my_name):
    try:
        entries = os.listdir(gate_dir)
    except OSError:
        return False
    for name in entries:
        if not name.startswith("active.") or name == my_name:
            continue
        path = os.path.join(gate_dir, name)
        try:
            fd = os.open(path, os.O_RDWR)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError:
            return True
        finally:
            os.close(fd)
    return False


def _acquire_mem_gate(worker_id, min_avail_mb, max_wait=120.0):
    """Hold an active-worker lock while a test runs; pause admission under low RAM.

    When MemAvailable drops below min_avail_mb and at least one other xdist worker
    is already running a test, wait until memory recovers or no other worker is
    active (preventing deadlock). When memory is between min_avail_mb and
    min_avail_mb + 2048 MB, stagger admissions slightly so newly started nodes
    allocate before the next worker checks MemAvailable.
    """
    gate_dir = os.path.join(tempfile.gettempdir(), f"cln-memgate-{os.getppid()}")
    os.makedirs(gate_dir, exist_ok=True)
    gate_path = os.path.join(gate_dir, "gate.lock")
    my_name = f"active.{worker_id}"
    my_path = os.path.join(gate_dir, my_name)

    deadline = time.monotonic() + max_wait
    while True:
        with open(gate_path, "a+") as gate_f:
            fcntl.flock(gate_f, fcntl.LOCK_EX)
            avail = _mem_available_mb()
            now = time.monotonic()
            should_wait = False
            if avail is not None and now < deadline:
                if avail < min_avail_mb and _other_workers_active(gate_dir, my_name):
                    should_wait = True
                elif avail < min_avail_mb + 2048 and _other_workers_active(gate_dir, my_name):
                    gate_f.seek(0)
                    try:
                        last_admit = float(gate_f.read().strip() or "0")
                    except ValueError:
                        last_admit = 0.0
                    if now - last_admit < 2.0:
                        should_wait = True

            if not should_wait:
                active_fd = os.open(my_path, os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(active_fd, fcntl.LOCK_EX)
                gate_f.seek(0)
                gate_f.truncate()
                gate_f.write(f"{now:.3f}\n")
                gate_f.flush()
                return active_fd
        time.sleep(0.5)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    min_avail_mb = int(os.environ.get("PYTEST_MIN_AVAIL_MB", "0") or "0")
    worker_id = getattr(item.config, "workerinput", {}).get("workerid")
    active_fd = None
    if min_avail_mb > 0 and worker_id and _mem_available_mb() is not None:
        active_fd = _acquire_mem_gate(worker_id, min_avail_mb)
    try:
        yield
    finally:
        if active_fd is not None:
            try:
                fcntl.flock(active_fd, fcntl.LOCK_UN)
            finally:
                os.close(active_fd)


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

    shutil.rmtree(
        os.path.join(tempfile.gettempdir(), f"cln-memgate-{os.getpid()}"),
        ignore_errors=True,
    )

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
