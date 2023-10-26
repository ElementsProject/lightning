import pytest
import subprocess
from urllib import request
import os
import json
from time import time
import unittest

server = os.environ.get("CI_SERVER", None)

github_sha = (
    subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("ASCII").strip()
)

github_ref_name = (
    subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    .decode("ASCII")
    .strip()
)

run_id = os.environ.get("GITHUB_RUN_ID", None)
run_number = os.environ.get("GITHUB_RUN_NUMBER", None)

result = {
    "github_repository": os.environ.get("GITHUB_REPOSITORY", None),
    "github_sha": os.environ.get("GITHUB_SHA", github_sha),
    "github_ref": os.environ.get("GITHUB_REF", None),
    "github_ref_name": github_ref_name,
    "github_run_id": int(run_id) if run_id else None,
    "github_head_ref": os.environ.get("GITHUB_HEAD_REF", None),
    "github_run_number": int(run_number) if run_number else None,
    "github_base_ref": os.environ.get("GITHUB_BASE_REF", None),
    "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", None),
}


@pytest.hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    global result
    result = result.copy()
    result["testname"] = pyfuncitem.name
    result["start_time"] = int(time())
    outcome = yield
    result["end_time"] = int(time())
    # outcome.excinfo may be None or a (cls, val, tb) tuple

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

        warnings.warn(f"Error reporting testrun: {e}: {e.read()}")
