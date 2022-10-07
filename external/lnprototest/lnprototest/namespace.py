#! /usr/bin/python3
import pyln.spec.bolt1
import pyln.spec.bolt2
import pyln.spec.bolt7
from pyln.proto.message import MessageNamespace
from .signature import SigType
from typing import List


def make_namespace(csv: List[str]) -> MessageNamespace:
    """Load a namespace, replacing signature type"""
    ns = MessageNamespace()
    # We replace the fundamental signature type with our custom type,
    # then we load in all the csv files so they use it.
    ns.fundamentaltypes["signature"] = SigType()
    ns.load_csv(csv)
    return ns


def peer_message_namespace() -> MessageNamespace:
    """Namespace containing all the peer messages"""
    return make_namespace(
        pyln.spec.bolt1.csv + pyln.spec.bolt2.csv + pyln.spec.bolt7.csv
    )


def namespace() -> MessageNamespace:
    return event_namespace


def assign_namespace(ns: MessageNamespace) -> None:
    global event_namespace
    event_namespace = ns


# By default, include all peer message bolts
event_namespace = peer_message_namespace()
