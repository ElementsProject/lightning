#! /usr/bin/python3
import pytest
import importlib
import lnprototest
import pyln.spec.bolt1
import pyln.spec.bolt2
import pyln.spec.bolt7
from pyln.proto.message import MessageNamespace
from typing import Any, Callable, Generator, List


def pytest_addoption(parser: Any) -> None:
    parser.addoption(
        "--runner",
        action="store",
        help="runner to use",
        default="lnprototest.DummyRunner",
    )
    parser.addoption(
        "--runner-args",
        action="append",
        help="parameters for runner to use",
        default=[],
    )


@pytest.fixture()  # type: ignore
def runner(pytestconfig: Any) -> Any:
    parts = pytestconfig.getoption("runner").rpartition(".")
    runner = importlib.import_module(parts[0]).__dict__[parts[2]](pytestconfig)
    yield runner
    runner.teardown()


@pytest.fixture()
def namespaceoverride(
    pytestconfig: Any,
) -> Generator[Callable[[MessageNamespace], None], None, None]:
    """Use this if you want to override the message namespace"""

    def _setter(newns: MessageNamespace) -> None:
        lnprototest.assign_namespace(newns)

    yield _setter
    # Restore it
    lnprototest.assign_namespace(lnprototest.peer_message_namespace())


@pytest.fixture()
def with_proposal(
    pytestconfig: Any,
) -> Generator[Callable[[List[str]], None], None, None]:
    """Use this to add additional messages to the namespace
    Useful for testing proposed (but not yet merged) spec mods.  Noop if it seems already merged."""

    def _setter(proposal_csv: List[str]) -> None:
        # Testing first line is cheap, pretty effective.
        if proposal_csv[0] not in (
            pyln.spec.bolt1.csv + pyln.spec.bolt2.csv + pyln.spec.bolt7.csv
        ):
            # We merge *csv*, because then you can add tlv entries; merging
            # namespaces with duplicate TLVs complains of a clash.
            lnprototest.assign_namespace(
                lnprototest.make_namespace(
                    pyln.spec.bolt1.csv
                    + pyln.spec.bolt2.csv
                    + pyln.spec.bolt7.csv
                    + proposal_csv
                )
            )

    yield _setter

    # Restore it
    lnprototest.assign_namespace(lnprototest.peer_message_namespace())
