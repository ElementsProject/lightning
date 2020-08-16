#! /usr/bin/python3
from pyln.proto.message import MessageNamespace
import pyln.spec.bolt7 as bolt7


# FIXME: more tests
def test_bolt_07_csv():
    MessageNamespace(bolt7.csv)


def test_bolt_07_subtypes():
    for t in ['{timestamp_node_id_1=1,timestamp_node_id_2=2}']:
        vals, _ = bolt7.channel_update_timestamps.val_from_str(t)
        assert bolt7.channel_update_timestamps.val_to_str(vals, None) == t
