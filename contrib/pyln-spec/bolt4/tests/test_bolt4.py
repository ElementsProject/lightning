#! /usr/bin/python3
from pyln.proto.message import MessageNamespace
import pyln.spec.bolt4 as bolt4


# FIXME: more tests
def test_bolt_04_csv():
    MessageNamespace(bolt4.csv)
