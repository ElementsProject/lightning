#! /usr/bin/env python3
# Variations on init exchange.
# Spec: MUST respond to known feature bits as specified in [BOLT #9](09-features.md).

from lnprototest import (
    Runner,
    Event,
    Sequence,
    TryAll,
    Connect,
    Disconnect,
    EventError,
    ExpectMsg,
    Msg,
    ExpectError,
    has_bit,
    bitfield,
    bitfield_len,
    SpecFileError,
)
from lnprototest.stash import rcvd
import pyln.spec.bolt1
from pyln.proto.message import Message
from typing import List, Any

import functools
import pytest


# BOLT #1: The sending node:
# ...
# - SHOULD NOT set features greater than 13 in `globalfeatures`.
def no_gf13(event: Event, msg: Message, runner: "Runner") -> None:
    for i in range(14, bitfield_len(msg.fields["globalfeatures"])):
        if has_bit(msg.fields["globalfeatures"], i):
            raise EventError(event, "globalfeatures bit {} set".format(i))


def no_feature(
    featurebits: List[int], event: Event, msg: Message, runner: "Runner"
) -> None:
    for bit in featurebits:
        if has_bit(msg.fields["features"], bit):
            raise EventError(
                event, "features set bit {} unexpected: {}".format(bit, msg.to_str())
            )


def has_feature(
    featurebits: List[int], event: Event, msg: Message, runner: "Runner"
) -> None:
    for bit in featurebits:
        if not has_bit(msg.fields["features"], bit):
            raise EventError(
                event, "features set bit {} unset: {}".format(bit, msg.to_str())
            )


def has_one_feature(
    featurebits: List[int], event: Event, msg: Message, runner: "Runner"
) -> None:
    has_any = False
    for bit in featurebits:
        if has_bit(msg.fields["features"], bit):
            has_any = True

    if not has_any:
        raise EventError(event, "none of {} set: {}".format(featurebits, msg.to_str()))


def test_namespace_override(runner: Runner, namespaceoverride: Any) -> None:
    # Truncate the namespace to just BOLT1
    namespaceoverride(pyln.spec.bolt1.namespace)

    # Try to send a message that's not in BOLT1
    with pytest.raises(SpecFileError, match=r"Unknown msgtype open_channel"):
        Msg("open_channel")


def test_init(runner: Runner, namespaceoverride: Any) -> None:
    # We override default namespace since we only need BOLT1
    namespaceoverride(pyln.spec.bolt1.namespace)
    test = [
        Connect(connprivkey="03"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=""),
        # optionally disconnect that first one
        TryAll([], Disconnect()),
        Connect(connprivkey="02"),
        TryAll(
            # Even if we don't send anything, it should send init.
            [ExpectMsg("init")],
            # Minimal possible init message.
            # BOLT #1:
            # The sending node:
            #  - MUST send `init` as the first Lightning message for any connection.
            [ExpectMsg("init"), Msg("init", globalfeatures="", features="")],
            # BOLT #1:
            # The sending node:...
            #  - SHOULD NOT set features greater than 13 in `globalfeatures`.
            [
                ExpectMsg("init", if_match=no_gf13),
                # BOLT #1:
                # The receiving node:...
                #  - upon receiving unknown _odd_ feature bits that are non-zero:
                #    - MUST ignore the bit.
                # init msg with unknown odd global bit (99): no error
                Msg("init", globalfeatures=bitfield(99), features=""),
            ],
            # Sanity check that bits 98 and 99 are not used!
            [
                ExpectMsg("init", if_match=functools.partial(no_feature, [98, 99])),
                # BOLT #1:
                # The receiving node:...
                #  - upon receiving unknown _odd_ feature bits that are non-zero:
                #    - MUST ignore the bit.
                # init msg with unknown odd local bit (99): no error
                Msg("init", globalfeatures="", features=bitfield(99)),
            ],
            # BOLT #1:
            # The receiving node: ...
            #  - upon receiving unknown _even_ feature bits that are non-zero:
            #    - MUST fail the connection.
            [
                ExpectMsg("init"),
                Msg("init", globalfeatures="", features=bitfield(98)),
                ExpectError(),
            ],
            # init msg with unknown even global bit (98): you will error
            [
                ExpectMsg("init"),
                Msg("init", globalfeatures=bitfield(98), features=""),
                ExpectError(),
            ],
            # If you don't support `option_data_loss_protect`, you will be ok if
            # we ask for it.
            Sequence(
                [
                    ExpectMsg("init", if_match=functools.partial(no_feature, [0, 1])),
                    Msg("init", globalfeatures="", features=bitfield(1)),
                ],
                enable=not runner.has_option("option_data_loss_protect"),
            ),
            # If you don't support `option_data_loss_protect`, you will error if
            # we require it.
            Sequence(
                [
                    ExpectMsg("init", if_match=functools.partial(no_feature, [0, 1])),
                    Msg("init", globalfeatures="", features=bitfield(0)),
                    ExpectError(),
                ],
                enable=not runner.has_option("option_data_loss_protect"),
            ),
            # If you support `option_data_loss_protect`, you will advertize it odd.
            Sequence(
                [ExpectMsg("init", if_match=functools.partial(has_feature, [1]))],
                enable=(runner.has_option("option_data_loss_protect") == "odd"),
            ),
            # If you require `option_data_loss_protect`, you will advertize it even.
            Sequence(
                [ExpectMsg("init", if_match=functools.partial(has_feature, [0]))],
                enable=(runner.has_option("option_data_loss_protect") == "even"),
            ),
            # If you don't support `option_anchor_outputs`, you will be ok if
            # we ask for it.
            Sequence(
                [
                    ExpectMsg("init", if_match=functools.partial(no_feature, [20, 21])),
                    Msg("init", globalfeatures="", features=bitfield(21)),
                ],
                enable=not runner.has_option("option_anchor_outputs"),
            ),
            # If you don't support `option_anchor_outputs`, you will error if
            # we require it.
            Sequence(
                [
                    ExpectMsg("init", if_match=functools.partial(no_feature, [20, 21])),
                    Msg("init", globalfeatures="", features=bitfield(20)),
                    ExpectError(),
                ],
                enable=not runner.has_option("option_anchor_outputs"),
            ),
            # If you support `option_anchor_outputs`, you will advertize it odd.
            Sequence(
                [ExpectMsg("init", if_match=functools.partial(has_feature, [21]))],
                enable=(runner.has_option("option_anchor_outputs") == "odd"),
            ),
            # If you require `option_anchor_outputs`, you will advertize it even.
            Sequence(
                [ExpectMsg("init", if_match=functools.partial(has_feature, [20]))],
                enable=(runner.has_option("option_anchor_outputs") == "even"),
            ),
            # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #9:
            # | Bits  | Name                    | ... | Dependencies
            # ...
            # | 12/13 | `option_static_remotekey` |
            # ...
            # | 20/21 | `option_anchor_outputs` | ... | `option_static_remotekey` |
            # If you support `option_anchor_outputs`, you will
            # advertize option_static_remotekey.
            Sequence(
                [
                    ExpectMsg(
                        "init", if_match=functools.partial(has_one_feature, [12, 13])
                    )
                ],
                enable=(runner.has_option("option_anchor_outputs") is not None),
            ),
            # You should always handle us echoing your own features back!
            [ExpectMsg("init"), Msg("init", globalfeatures=rcvd(), features=rcvd())],
        ),
    ]

    runner.run(test)
