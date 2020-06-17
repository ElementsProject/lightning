#! /usr/bin/python3
from pyln.proto.message import MessageNamespace
import pyln.spec.bolt2 as bolt2


# FIXME: more tests
def test_bolt_02_csv():
    MessageNamespace(bolt2.csv)
