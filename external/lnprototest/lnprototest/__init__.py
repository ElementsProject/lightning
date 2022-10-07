"""lnprototest: a framework and test suite for checking lightning spec protocol compliance.

This package is unusual, in that its main purpose is to carry the unit
tests, which can be run against a Lightning node implementation, using
an adapter called a 'Runner'.  Two runners are included: the
DummyRunner which is the default, and mainly useful to sanity check
the tests themselves, and clightning.Runner.

The documentation for the classes themselves should cover much of the
reference material, and the tutorial should get you started.

"""
from .errors import EventError, SpecFileError
from .event import (
    Event,
    Connect,
    Disconnect,
    Msg,
    RawMsg,
    ExpectMsg,
    MustNotMsg,
    Block,
    ExpectTx,
    FundChannel,
    InitRbf,
    Invoice,
    AddHtlc,
    CheckEq,
    ExpectError,
    ResolvableInt,
    ResolvableStr,
    Resolvable,
    ResolvableBool,
    msat,
    negotiated,
    DualFundAccept,
    Wait,
    CloseChannel,
)
from .structure import Sequence, OneOf, AnyOrder, TryAll
from .runner import (
    Runner,
    Conn,
    remote_revocation_basepoint,
    remote_payment_basepoint,
    remote_delayed_payment_basepoint,
    remote_htlc_basepoint,
    remote_per_commitment_point,
    remote_per_commitment_secret,
    remote_funding_pubkey,
    remote_funding_privkey,
)
from .dummyrunner import DummyRunner
from .namespace import (
    peer_message_namespace,
    namespace,
    assign_namespace,
    make_namespace,
)
from .bitfield import bitfield, has_bit, bitfield_len
from .signature import SigType, Sig
from .keyset import KeySet
from .commit_tx import Commit, HTLC, UpdateCommit
from .utils import Side, regtest_hash, privkey_expand, wait_for
from .funding import (
    AcceptFunding,
    CreateFunding,
    CreateDualFunding,
    Funding,
    AddInput,
    AddOutput,
    FinalizeFunding,
    AddWitnesses,
)
from .proposals import dual_fund_csv, channel_type_csv

__all__ = [
    "EventError",
    "SpecFileError",
    "Resolvable",
    "ResolvableInt",
    "ResolvableStr",
    "ResolvableBool",
    "Event",
    "Connect",
    "Disconnect",
    "DualFundAccept",
    "CreateDualFunding",
    "AddInput",
    "AddOutput",
    "FinalizeFunding",
    "AddWitnesses",
    "Msg",
    "RawMsg",
    "ExpectMsg",
    "Block",
    "ExpectTx",
    "FundChannel",
    "InitRbf",
    "Invoice",
    "AddHtlc",
    "ExpectError",
    "Sequence",
    "OneOf",
    "AnyOrder",
    "TryAll",
    "CheckEq",
    "MustNotMsg",
    "SigType",
    "Sig",
    "DummyRunner",
    "Runner",
    "Conn",
    "KeySet",
    "peer_message_namespace",
    "namespace",
    "assign_namespace",
    "make_namespace",
    "bitfield",
    "has_bit",
    "bitfield_len",
    "msat",
    "negotiated",
    "remote_revocation_basepoint",
    "remote_payment_basepoint",
    "remote_delayed_payment_basepoint",
    "remote_htlc_basepoint",
    "remote_per_commitment_point",
    "remote_per_commitment_secret",
    "remote_funding_pubkey",
    "remote_funding_privkey",
    "Commit",
    "HTLC",
    "UpdateCommit",
    "Side",
    "AcceptFunding",
    "CreateFunding",
    "Funding",
    "regtest_hash",
    "privkey_expand",
    "Wait",
    "dual_fund_csv",
    "channel_type_csv",
    "wait_for",
    "CloseChannel",
]
