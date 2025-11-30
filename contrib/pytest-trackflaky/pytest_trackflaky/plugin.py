"""pytest-trackflaky plugin implementation."""

import pytest
import subprocess
from urllib import request
import os
import json
from time import time
import unittest
import threading


# Global state for run tracking
_run_id = None
_run_id_lock = threading.Lock()
server = os.environ.get("CI_SERVER_URL", None)


class SnowflakeGenerator:
    """
    Generates Twitter-style Snowflake IDs.

    Format (64 bits):
    - 41 bits: timestamp in milliseconds since custom epoch
    - 10 bits: worker/machine ID
    - 12 bits: sequence number
    """

    # Custom epoch (2024-01-01 00:00:00 UTC in milliseconds)
    EPOCH = 1704067200000

    # Bit allocation
    TIMESTAMP_BITS = 41
    WORKER_BITS = 10
    SEQUENCE_BITS = 12

    # Max values
    MAX_WORKER_ID = (1 << WORKER_BITS) - 1
    MAX_SEQUENCE = (1 << SEQUENCE_BITS) - 1

    # Bit shifts
    TIMESTAMP_SHIFT = WORKER_BITS + SEQUENCE_BITS
    WORKER_SHIFT = SEQUENCE_BITS

    def __init__(self, worker_id=None):
        """Initialize the snowflake generator."""
        if worker_id is None:
            # Try to get worker ID from environment or use process ID
            worker_id = os.getpid() & self.MAX_WORKER_ID

        if worker_id > self.MAX_WORKER_ID or worker_id < 0:
            raise ValueError(f"Worker ID must be between 0 and {self.MAX_WORKER_ID}")

        self.worker_id = worker_id
        self.sequence = 0
        self.last_timestamp = -1
        self.lock = threading.Lock()

    def _current_timestamp(self):
        """Get current timestamp in milliseconds since epoch."""
        return int(time() * 1000)

    def generate(self):
        """Generate a new Snowflake ID."""
        with self.lock:
            timestamp = self._current_timestamp() - self.EPOCH

            if timestamp < self.last_timestamp:
                raise Exception("Clock moved backwards. Refusing to generate ID.")

            if timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & self.MAX_SEQUENCE
                if self.sequence == 0:
                    # Sequence exhausted, wait for next millisecond
                    while timestamp <= self.last_timestamp:
                        timestamp = self._current_timestamp() - self.EPOCH
            else:
                self.sequence = 0

            self.last_timestamp = timestamp

            # Combine all parts
            snowflake_id = (
                (timestamp << self.TIMESTAMP_SHIFT)
                | (self.worker_id << self.WORKER_SHIFT)
                | self.sequence
            )

            return snowflake_id


# Global snowflake generator
_snowflake_gen = SnowflakeGenerator()


def get_git_sha():
    """Get the current git commit SHA."""
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "HEAD"])
            .decode("ASCII")
            .strip()
        )
    except subprocess.CalledProcessError:
        return None


def get_git_branch():
    """Get the current git branch name."""
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
            .decode("ASCII")
            .strip()
        )
    except subprocess.CalledProcessError:
        return None


def get_git_repository():
    """
    Detect the git repository from remotes.

    Checks refs in order: master@upstream, main@upstream, master@origin, main@origin.
    Returns repository in "owner/repo" format (e.g., "ElementsProject/lightning").
    """
    # Check these refs in order
    refs_to_check = [
        "master@upstream",
        "main@upstream",
        "master@origin",
        "main@origin"
    ]

    for ref in refs_to_check:
        try:
            # Try to get the URL for this ref
            remote_url = (
                subprocess.check_output(
                    ["git", "config", "--get", f"remote.{ref.split('@')[1]}.url"],
                    stderr=subprocess.DEVNULL
                )
                .decode("ASCII")
                .strip()
            )

            # Parse the URL to extract owner/repo
            # Handle various formats:
            # - https://github.com/owner/repo.git
            # - git@github.com:owner/repo.git
            # - https://github.com/owner/repo

            if remote_url.startswith("git@"):
                # SSH format: git@github.com:owner/repo.git
                path = remote_url.split(":", 1)[1]
            elif "://" in remote_url:
                # HTTPS format: https://github.com/owner/repo.git
                path = remote_url.split("://", 1)[1]
                # Remove the domain part
                if "/" in path:
                    path = "/".join(path.split("/")[1:])
            else:
                # Unknown format, try next ref
                continue

            # Remove .git suffix if present
            if path.endswith(".git"):
                path = path[:-4]

            # Ensure we have owner/repo format
            parts = path.split("/")
            if len(parts) >= 2:
                return f"{parts[-2]}/{parts[-1]}"

        except subprocess.CalledProcessError:
            # This ref doesn't exist, try the next one
            continue

    return None


def get_run_id():
    """Get or generate the run ID for this test session."""
    global _run_id
    with _run_id_lock:
        if _run_id is None:
            _run_id = _snowflake_gen.generate()
        return _run_id


def set_run_id(run_id):
    """Set the run ID (used by workers to inherit from main process)."""
    global _run_id
    with _run_id_lock:
        _run_id = run_id


def get_base_result():
    """Collect base result information from environment and git."""
    github_sha = get_git_sha()
    github_ref_name = get_git_branch()
    github_run_id = os.environ.get("GITHUB_RUN_ID", None)
    run_number = os.environ.get("GITHUB_RUN_NUMBER", None)

    # Auto-detect repository from git remotes if not in environment
    github_repository = os.environ.get("GITHUB_REPOSITORY", None)
    if not github_repository:
        github_repository = get_git_repository()

    return {
        "run_id": get_run_id(),
        "github_repository": github_repository,
        "github_sha": os.environ.get("GITHUB_SHA", github_sha),
        "github_ref": os.environ.get("GITHUB_REF", None),
        "github_ref_name": github_ref_name,
        "github_run_id": int(github_run_id) if github_run_id else None,
        "github_head_ref": os.environ.get("GITHUB_HEAD_REF", None),
        "github_run_number": int(run_number) if run_number else None,
        "github_base_ref": os.environ.get("GITHUB_BASE_REF", None),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", None),
    }


def pytest_configure(config):
    """Generate a unique run ID when pytest starts."""
    # Generate the run ID early so it's available for all tests
    get_run_id()


def pytest_report_header(config):
    """Add run ID to pytest header."""
    run_id = get_run_id()
    return f"Run ID: {run_id}, server: {server}"


def pytest_configure_node(node):
    """
    Configure worker nodes to inherit the run ID from the main process.

    This hook is called by pytest-xdist to configure worker nodes.
    """
    node.workerinput["trackflaky_run_id"] = get_run_id()


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """
    Initialize run ID from worker input if this is a worker process.

    This runs on worker nodes to receive the run ID from the main process.
    """
    if hasattr(session.config, "workerinput"):
        # We're in a worker process
        workerinput = session.config.workerinput
        if "trackflaky_run_id" in workerinput:
            set_run_id(workerinput["trackflaky_run_id"])


@pytest.hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    """Hook into pytest test execution to track test outcomes."""

    result = get_base_result()
    result["testname"] = pyfuncitem.name
    result["start_time"] = int(time())

    outcome = yield

    result["end_time"] = int(time())

    if outcome.excinfo is None:
        result["outcome"] = "success"
    elif outcome.excinfo[0] == unittest.case.SkipTest:
        result["outcome"] = "skip"
    else:
        result["outcome"] = "fail"

    print(result)

    if not server:
        return

    try:
        req = request.Request(f"{server}/hook/test", method="POST")
        req.add_header("Content-Type", "application/json")

        request.urlopen(
            req,
            data=json.dumps(result).encode("ASCII"),
        )
    except ConnectionError as e:
        print(f"Could not report testrun: {e}")
    except Exception as e:
        import warnings

        warnings.warn(f"Error reporting testrun: {e}")
